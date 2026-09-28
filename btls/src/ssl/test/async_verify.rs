use super::server::{ClientSslBuilder, Server};
use crate::ssl::{
    ErrorCode, HandshakeError, SslContextBuilder, SslMethod, SslRef, SslStream, SslVerifyMode,
    VerifyJob,
};
use crate::x509::{X509VerifyError, X509VerifyResult};
use std::io::Read;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Wake, Waker};
use std::thread;

/// 2025-01-01, when the test certificates are valid.
const VERIFY_TIME: i64 = 1_735_689_600;

/// 2200-01-01, when they have expired.
const EXPIRED_TIME: i64 = 7_258_118_400;

/// Makes `ssl` expect the certificate of [Server] and verify it at [VERIFY_TIME].
fn expect_server_cert(ssl: &mut SslRef) {
    ssl.param_mut().set_time(VERIFY_TIME as _);
    ssl.param_mut().set_host("foobar.com").unwrap();
}

/// A waker that records that it was woken.
#[derive(Default)]
struct Woken {
    woken: Mutex<bool>,
    cond: Condvar,
}

impl Wake for Woken {
    fn wake(self: Arc<Self>) {
        *self.woken.lock().unwrap() = true;
        self.cond.notify_all();
    }
}

impl Woken {
    fn wait(&self) {
        let mut woken = self.woken.lock().unwrap();
        while !*woken {
            woken = self.cond.wait(woken).unwrap();
        }
    }
}

/// Runs verification jobs on threads of their own.
fn spawn_thread(job: VerifyJob) {
    thread::spawn(job);
}

/// Connects with a task waker set, so that the handshake waits for the verification job, and
/// finishes the handshake once the job has woken it. A failure comes with the error and the
/// verify result.
fn connect_async(
    mut client: ClientSslBuilder,
) -> Result<SslStream<TcpStream>, (String, X509VerifyResult)> {
    let woken = Arc::new(Woken::default());
    client
        .ssl()
        .set_task_waker(Some(Waker::from(woken.clone())));
    let mid = match client.connect_err() {
        HandshakeError::WouldBlock(mid) => mid,
        HandshakeError::Failure(mid) => {
            return Err((mid.error().to_string(), mid.ssl().verify_result()))
        }
        HandshakeError::SetupFailure(e) => panic!("{e}"),
    };
    assert_eq!(mid.error().code(), ErrorCode::WANT_CERTIFICATE_VERIFY);
    woken.wait();
    match mid.handshake() {
        Ok(stream) => Ok(stream),
        Err(HandshakeError::Failure(mid)) => {
            Err((mid.error().to_string(), mid.ssl().verify_result()))
        }
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn handshake_waits_for_job() {
    let server = Server::builder().build();
    let mut client = server.client_with_root_ca();
    let (jobs, queued) = mpsc::channel::<VerifyJob>();
    let jobs = Mutex::new(jobs);
    client
        .ctx()
        .set_async_default_verify(move |job| jobs.lock().unwrap().send(job).unwrap());
    let client = client.build();
    let mut client = client.builder();
    expect_server_cert(client.ssl());
    let woken = Arc::new(Woken::default());
    client
        .ssl()
        .set_task_waker(Some(Waker::from(woken.clone())));

    let HandshakeError::WouldBlock(mid) = client.connect_err() else {
        panic!("the handshake did not wait for the verification");
    };
    assert_eq!(mid.error().code(), ErrorCode::WANT_CERTIFICATE_VERIFY);
    let job = queued.try_recv().expect("no verification job");

    // Until the job has run, the handshake keeps waiting.
    let Err(HandshakeError::WouldBlock(mid)) = mid.handshake() else {
        panic!("the handshake went on without the verification");
    };
    assert_eq!(mid.error().code(), ErrorCode::WANT_CERTIFICATE_VERIFY);

    let main = thread::current().id();
    thread::spawn(move || {
        assert_ne!(thread::current().id(), main);
        job();
    })
    .join()
    .unwrap();
    woken.wait();

    let mut stream = mid.handshake().unwrap();
    stream.read_exact(&mut [0]).unwrap();
    assert_eq!(stream.ssl().verify_result(), Ok(()));
    assert!(queued.try_recv().is_err(), "a second verification job");
}

#[test]
fn verifies_inline_without_task_waker() {
    static SPAWNED: AtomicBool = AtomicBool::new(false);

    let server = Server::builder().build();
    let mut client = server.client_with_root_ca();
    client.ctx().set_async_default_verify(|job| {
        SPAWNED.store(true, Ordering::SeqCst);
        job();
    });
    let client = client.build();
    let mut client = client.builder();
    expect_server_cert(client.ssl());

    client.connect();
    assert!(!SPAWNED.load(Ordering::SeqCst));
}

/// A client with the built-in verification and one with verification in a job fail with the
/// same errors and verify results, and the same alerts reach the server: untrusted, expired and
/// for another host.
#[test]
fn failures_match_builtin_verification() {
    type Setup = fn(&mut SslRef);
    let cases: [(bool, Setup, &str); 3] = [
        (false, expect_server_cert, "[TLSV1_ALERT_UNKNOWN_CA]"),
        (
            true,
            |ssl| {
                ssl.param_mut().set_time(EXPIRED_TIME as _);
                ssl.param_mut().set_host("foobar.com").unwrap();
            },
            "[SSLV3_ALERT_CERTIFICATE_EXPIRED]",
        ),
        (
            true,
            |ssl| {
                ssl.param_mut().set_time(VERIFY_TIME as _);
                ssl.param_mut().set_host("example.com").unwrap();
            },
            "[SSLV3_ALERT_BAD_CERTIFICATE]",
        ),
    ];

    for (root_ca, setup, alert) in cases {
        let server_errors = Arc::new(Mutex::new(Vec::new()));
        let seen = server_errors.clone();
        let mut server = Server::builder();
        server.expected_connections_count(2);
        server.err_cb(move |err| {
            let HandshakeError::Failure(mid) = err else {
                panic!("expected a failure");
            };
            seen.lock().unwrap().push(mid.error().to_string());
        });
        let server = server.build();
        let client_builder = || {
            let mut client = if root_ca {
                server.client_with_root_ca()
            } else {
                server.client()
            };
            client.ctx().set_verify(SslVerifyMode::PEER);
            client
        };

        let client = client_builder().build();
        let mut builtin = client.builder();
        setup(builtin.ssl());
        let HandshakeError::Failure(mid) = builtin.connect_err() else {
            panic!("expected a failure");
        };
        let builtin_error = mid.error().to_string();
        let builtin_result = mid.ssl().verify_result();
        assert!(builtin_error.contains("CERTIFICATE_VERIFY_FAILED"));
        assert!(builtin_result.is_err());

        let mut client = client_builder();
        client.ctx().set_async_default_verify(spawn_thread);
        let client = client.build();
        let mut offloaded = client.builder();
        setup(offloaded.ssl());
        let (error, result) = connect_async(offloaded).map(|_| ()).unwrap_err();
        assert_eq!(error, builtin_error);
        assert_eq!(result, builtin_result);

        drop(server);
        let server_errors = server_errors.lock().unwrap();
        assert_eq!(*server_errors, [alert, alert], "{builtin_result:?}");
    }
}

#[test]
fn dropped_job_fails_handshake() {
    let mut server = Server::builder();
    server.err_cb(|err| {
        let HandshakeError::Failure(mid) = err else {
            panic!("expected a failure");
        };
        assert_eq!(mid.error().to_string(), "[TLSV1_ALERT_INTERNAL_ERROR]");
    });
    let server = server.build();
    let mut client = server.client_with_root_ca();
    client.ctx().set_verify(SslVerifyMode::PEER);
    client.ctx().set_async_default_verify(drop);
    let client = client.build();
    let mut client = client.builder();
    expect_server_cert(client.ssl());

    let (error, result) = connect_async(client).map(|_| ()).unwrap_err();
    assert!(error.contains("CERTIFICATE_VERIFY_FAILED"), "{error}");
    // No verify result to report.
    assert_eq!(result, Err(X509VerifyError::APPLICATION_VERIFICATION));
}

/// A verify callback may use the `Ssl`, which a job on another thread cannot give it, so the
/// verification fails instead of skipping the callback.
#[test]
fn verify_callback_fails_closed() {
    static SPAWNED: AtomicBool = AtomicBool::new(false);

    let mut server = Server::builder();
    server.should_error();
    let server = server.build();
    let mut client = server.client_with_root_ca();
    client
        .ctx()
        .set_verify_callback(SslVerifyMode::PEER, |preverify_ok, _| preverify_ok);
    client.ctx().set_async_default_verify(|job| {
        SPAWNED.store(true, Ordering::SeqCst);
        spawn_thread(job);
    });
    let client = client.build();
    let mut client = client.builder();
    expect_server_cert(client.ssl());

    let (error, _) = connect_async(client).map(|_| ()).unwrap_err();
    assert!(error.contains("CERTIFICATE_VERIFY_FAILED"), "{error}");
    assert!(!SPAWNED.load(Ordering::SeqCst));
}

/// With `SslVerifyMode::NONE`, a failed verification does not fail the handshake and leaves its
/// verify result, as with the built-in verification.
#[test]
fn verify_mode_none_ignores_failure() {
    let server = Server::builder().build();
    let client = server.client().build();
    let mut client = client.builder();
    client.ssl().set_verify(SslVerifyMode::NONE);
    client.ssl().set_async_default_verify(spawn_thread);
    expect_server_cert(client.ssl());

    let mut stream = connect_async(client).unwrap();
    stream.read_exact(&mut [0]).unwrap();
    assert_eq!(
        stream.ssl().verify_result(),
        Err(X509VerifyError::UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
    );
}

/// Without X.509 support, configuring the verification panics instead of aborting the process in
/// BoringSSL, as the other verification settings do.
#[test]
#[should_panic = "This context is not configured for X.509 certificates"]
fn requires_x509_support() {
    let mut ctx = unsafe { SslContextBuilder::new(SslMethod::tls_with_buffer()) }.unwrap();
    ctx.set_async_default_verify(spawn_thread);
}

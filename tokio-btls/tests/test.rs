use std::{
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    sync::{mpsc, Arc, Mutex},
    time::Duration,
};

use btls::ssl::{
    self, Ssl, SslAcceptor, SslConnector, SslConnectorBuilder, SslFiletype, SslMethod, VerifyJob,
};
use btls::x509::X509VerifyResult;
use futures::future;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use tokio_btls::SslStream;

/// Needs network access. The roots of Google Trust Services come with the test (see
/// tests/gts-roots.pem), so that it does not depend on a system CA store, which BoringSSL does
/// not find on Windows.
#[tokio::test]
async fn google() {
    let addr = "google.com:443".to_socket_addrs().unwrap().next().unwrap();
    let stream = TcpStream::connect(&addr).await.unwrap();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("tests/gts-roots.pem").unwrap();
    let ssl = connector
        .build()
        .configure()
        .unwrap()
        .into_ssl("google.com")
        .unwrap();
    let mut stream = SslStream::new(ssl, stream).unwrap();

    Pin::new(&mut stream).connect().await.unwrap();

    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();

    let mut buf = vec![];
    stream.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);
    let response = response.trim_end();

    // any response code is fine
    assert!(response.starts_with("HTTP/1.0 "));
    assert!(response.ends_with("</html>") || response.ends_with("</HTML>"));
}

#[tokio::test]
async fn server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = async move {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_private_key_file("tests/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("tests/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();

        let ssl = Ssl::new(acceptor.context()).unwrap();
        let stream = listener.accept().await.unwrap().0;
        let mut stream = SslStream::new(ssl, stream).unwrap();

        Pin::new(&mut stream).accept().await.unwrap();

        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"asdf");

        stream.write_all(b"jkl;").await.unwrap();

        future::poll_fn(|ctx| Pin::new(&mut stream).poll_shutdown(ctx))
            .await
            .unwrap()
    };

    let client = async {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file("tests/cert.pem").unwrap();
        let ssl = connector
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();

        let stream = TcpStream::connect(&addr).await.unwrap();
        let mut stream = SslStream::new(ssl, stream).unwrap();

        Pin::new(&mut stream).connect().await.unwrap();

        stream.write_all(b"asdf").await.unwrap();

        let mut buf = vec![];
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"jkl;");
    };

    future::join(server, client).await;
}

/// 2025-01-01, when tests/cert.pem is valid.
const VERIFY_TIME: i64 = 1_735_689_600;

/// 2200-01-01, when it has expired.
const EXPIRED_TIME: i64 = 7_258_118_400;

/// Accepts `count` connections with tests/cert.pem and returns how each handshake ended.
async fn accept_handshakes(listener: TcpListener, count: usize) -> Vec<Result<(), String>> {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor
        .set_private_key_file("tests/key.pem", SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_certificate_chain_file("tests/cert.pem")
        .unwrap();
    let acceptor = acceptor.build();

    let mut results = Vec::new();
    for _ in 0..count {
        let ssl = Ssl::new(acceptor.context()).unwrap();
        let stream = listener.accept().await.unwrap().0;
        let mut stream = SslStream::new(ssl, stream).unwrap();
        let result = Pin::new(&mut stream).accept().await;
        if result.is_ok() {
            stream.write_all(b"jkl;").await.unwrap();
            stream.shutdown().await.unwrap();
        }
        results.push(result.map_err(|e| e.to_string()));
    }
    results
}

/// Connects to `addr` as `domain`, verifying the certificate at `time`. A failure comes with
/// the verify result.
async fn connect(
    addr: SocketAddr,
    connector: &SslConnector,
    domain: &str,
    time: i64,
) -> Result<SslStream<TcpStream>, (ssl::Error, X509VerifyResult)> {
    let mut ssl = connector.configure().unwrap().into_ssl(domain).unwrap();
    ssl.param_mut().set_time(time as _);
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut stream = SslStream::new(ssl, stream).unwrap();
    match Pin::new(&mut stream).connect().await {
        Ok(()) => Ok(stream),
        Err(e) => Err((e, stream.ssl().verify_result())),
    }
}

/// The certificate is verified on a blocking thread while the runtime goes on: the
/// verification waits until a task on the runtime's only thread has run after it started.
#[tokio::test]
async fn async_verification() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(accept_handshakes(listener, 1));

    let (job_started, started) = tokio::sync::oneshot::channel();
    let (runtime_ran, ran) = mpsc::channel();
    let observer = tokio::spawn(async move {
        started.await.unwrap();
        runtime_ran.send(()).unwrap();
    });
    let verification = Mutex::new(Some((job_started, ran)));
    let verified = Arc::new(Mutex::new(false));
    let done = verified.clone();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("tests/cert.pem").unwrap();
    connector.set_async_default_verify(move |job: VerifyJob| {
        let (job_started, ran) = verification
            .lock()
            .unwrap()
            .take()
            .expect("a second verification");
        let done = done.clone();
        tokio::task::spawn_blocking(move || {
            job_started.send(()).unwrap();
            ran.recv_timeout(Duration::from_secs(10))
                .expect("the runtime did not run while the certificate was verified");
            job();
            *done.lock().unwrap() = true;
        });
    });
    let connector = connector.build();

    let mut stream = connect(addr, &connector, "localhost", VERIFY_TIME)
        .await
        .unwrap();
    assert!(*verified.lock().unwrap());
    observer.await.unwrap();

    let mut buf = vec![];
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"jkl;");
    assert_eq!(server.await.unwrap(), [Ok(())]);
}

/// A certificate that fails verification on a blocking thread fails the handshake with the
/// same errors, on both ends, and verify result as with the built-in verification: untrusted,
/// expired and for another host.
#[tokio::test]
async fn async_verification_failures_match_sync() {
    let untrusted = || SslConnector::builder(SslMethod::tls()).unwrap();
    let trusted = || {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file("tests/cert.pem").unwrap();
        connector
    };
    type Builder<'a> = &'a dyn Fn() -> SslConnectorBuilder;
    let cases: [(Builder, &str, i64); 3] = [
        (&untrusted, "localhost", VERIFY_TIME),
        (&trusted, "localhost", EXPIRED_TIME),
        (&trusted, "example.com", VERIFY_TIME),
    ];

    for (builder, domain, time) in cases {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(accept_handshakes(listener, 2));

        let (sync, sync_result) = connect(addr, &builder().build(), domain, time)
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(
            sync.to_string().contains("CERTIFICATE_VERIFY_FAILED"),
            "{sync}"
        );

        let mut offloaded = builder();
        offloaded.set_async_default_verify(|job| {
            tokio::task::spawn_blocking(job);
        });
        let (error, result) = connect(addr, &offloaded.build(), domain, time)
            .await
            .map(|_| ())
            .unwrap_err();
        assert_eq!(error.code(), sync.code());
        assert_eq!(error.to_string(), sync.to_string());
        assert!(sync_result.is_err());
        assert_eq!(result, sync_result);

        let server_results = server.await.unwrap();
        assert!(server_results[0].is_err());
        assert_eq!(server_results[0], server_results[1]);
    }
}

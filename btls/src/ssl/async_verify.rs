//! BoringSSL's built-in certificate verification, run on another thread.

use super::async_callbacks::TASK_WAKER_INDEX;
use super::{Ssl, SslAlert, SslContextBuilder, SslRef, SslVerifyError, SslVerifyMode};
use crate::ex_data::Index;
use crate::ffi;
use crate::stack::{Stack, StackRef};
use crate::x509::store::{X509Store, X509StoreRef};
use crate::x509::{X509StoreContext, X509VerifyError, X509};
use foreign_types::{ForeignType, ForeignTypeRef};
use std::ffi::{c_int, c_long};
use std::mem;
use std::ptr;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use std::task::Waker;

/// A certificate verification handed to the spawner of
/// [`SslContextBuilder::set_async_default_verify`]. It may block and should run where that does
/// not hold up other work, such as `tokio::task::spawn_blocking`.
pub type VerifyJob = Box<dyn FnOnce() + Send>;

static PENDING_INDEX: LazyLock<Index<Ssl, Option<Pending>>> =
    LazyLock::new(|| Ssl::new_ex_index().unwrap());

/// The verify result of a failed verification, see [`verify_error`].
static VERIFY_ERROR_INDEX: LazyLock<Index<Ssl, c_int>> =
    LazyLock::new(|| Ssl::new_ex_index().unwrap());

impl SslContextBuilder {
    /// Verifies the peer's certificate chain the way BoringSSL's built-in verification does,
    /// but on another thread.
    ///
    /// When the peer's certificates arrive, the chain, the store BoringSSL would verify it
    /// against (see [`Self::set_verify_cert_store`]) and the connection's verification
    /// parameters, including the hostname to check, are captured on the handshake's thread.
    /// `spawn` then gets a [`VerifyJob`] that runs `X509_verify_cert` on them and should run it
    /// on a thread where blocking is fine, e.g. `|job| { tokio::task::spawn_blocking(job); }`.
    /// Until the job has finished, the handshake stops with
    /// [`ErrorCode::WANT_CERTIFICATE_VERIFY`](super::ErrorCode::WANT_CERTIFICATE_VERIFY): the
    /// job wakes the task waker ([`SslRef::set_task_waker`]) and the handshake continues when it
    /// is driven again. tokio-btls and the quinn-btls client do both. If no task waker is set,
    /// the job runs on the handshake's thread before the handshake continues.
    ///
    /// A failed verification fails the handshake as the built-in verification would: the alert
    /// that belongs to the verify result and `CERTIFICATE_VERIFY_FAILED`, unless the verify mode
    /// is [`SslVerifyMode::NONE`]. [`SslRef::verify_result`] reports the verify result, such as
    /// [`X509VerifyError::CERT_HAS_EXPIRED`], although BoringSSL records
    /// [`X509VerifyError::APPLICATION_VERIFICATION`] for it, as for any custom verification. A
    /// job that is dropped without running fails the verification with an internal error.
    ///
    /// Callbacks set with [`Self::set_verify_callback`], [`Self::set_cert_verify_callback`] or
    /// on the verify store take part in the built-in verification and may use the `Ssl`, so
    /// they cannot run on another thread: with one of them set, verification fails with an
    /// internal error. This replaces a custom verify callback and keeps the verify mode.
    ///
    /// # Panics
    ///
    /// This method panics if this context is not configured for X.509 certificates.
    ///
    #[doc(alias = "SSL_CTX_set_custom_verify")]
    pub fn set_async_default_verify<S>(&mut self, spawn: S)
    where
        S: Fn(VerifyJob) + Send + Sync + 'static,
    {
        // The verification needs the X.509 objects, and SSL_CTX_get_verify_mode aborts without.
        self.ctx.check_x509();
        let mode = unsafe { ffi::SSL_CTX_get_verify_mode(self.as_ptr()) };
        self.set_custom_verify_callback(SslVerifyMode::from_bits_retain(mode), move |ssl| {
            verify(ssl, &spawn)
        });
    }
}

impl SslRef {
    /// Like [`SslContextBuilder::set_async_default_verify`].
    ///
    /// # Panics
    ///
    /// This method panics if this `Ssl` is not configured for X.509 certificates.
    #[doc(alias = "SSL_set_custom_verify")]
    pub fn set_async_default_verify<S>(&mut self, spawn: S)
    where
        S: Fn(VerifyJob) + Send + Sync + 'static,
    {
        self.ssl_context().check_x509();
        let mode = unsafe { ffi::SSL_get_verify_mode(self.as_ptr()) };
        self.set_custom_verify_callback(SslVerifyMode::from_bits_retain(mode), move |ssl| {
            verify(ssl, &spawn)
        });
    }
}

/// The custom verify callback: starts a verification job on the first call and returns its
/// result on a later one.
fn verify(ssl: &mut SslRef, spawn: &dyn Fn(VerifyJob)) -> Result<(), SslVerifyError> {
    let waker = ssl.ex_data(*TASK_WAKER_INDEX).cloned().flatten();

    if let Some(pending) = ssl.ex_data_mut(*PENDING_INDEX).and_then(Option::take) {
        return match pending.task.poll(waker) {
            Some(outcome) => finish(ssl, &pending.chain, outcome),
            None => {
                ssl.replace_ex_data(*PENDING_INDEX, Some(pending));
                Err(SslVerifyError::Retry)
            }
        };
    }

    let (verification, chain) = Verification::new(ssl).map_err(SslVerifyError::Invalid)?;
    let Some(waker) = waker else {
        // Nothing would wake the handshake once the job is done.
        return finish(ssl, &chain, verification.run());
    };

    let task = Arc::new(Task(Mutex::new(State::Running(Some(waker)))));
    let job = Job {
        verification: Some(verification),
        task: task.clone(),
    };
    spawn(Box::new(move || job.run()));

    // `spawn` may have run the job already.
    if let Some(outcome) = task.poll(None) {
        return finish(ssl, &chain, outcome);
    }
    ssl.replace_ex_data(*PENDING_INDEX, Some(Pending { task, chain }));
    Err(SslVerifyError::Retry)
}

/// Turns the outcome of a job into the result of the custom verify callback.
fn finish(ssl: &mut SslRef, chain: &[X509], outcome: Outcome) -> Result<(), SslVerifyError> {
    // The handshake waits in the same state while the job runs, so the peer's chain is still
    // the one that was verified. Make sure of it: the result is only good for those
    // certificates.
    if !is_peer_chain(ssl, chain) {
        return Err(SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR));
    }

    match outcome {
        Outcome::Verified { ok: true, .. } => Ok(()),
        // As in ssl_crypto_x509_session_verify_cert_chain.
        Outcome::Verified { ok: false, error } => {
            if error != ffi::X509_V_OK {
                ssl.replace_ex_data(*VERIFY_ERROR_INDEX, error);
            }
            Err(SslVerifyError::Invalid(SslAlert(unsafe {
                ffi::SSL_alert_from_verify_result(error as c_long)
            })))
        }
        Outcome::Dropped => Err(SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR)),
    }
}

/// The verify result of a verification that failed: BoringSSL records
/// `X509_V_ERR_APPLICATION_VERIFICATION` when a custom verification fails, so
/// [`SslRef::verify_result`] reports this instead.
pub(super) fn verify_error(ssl: &SslRef) -> Option<X509VerifyError> {
    let error = *ssl.ex_data(*VERIFY_ERROR_INDEX)?;
    unsafe { X509VerifyError::from_raw(error) }.err()
}

impl SslRef {
    /// Whether an asynchronous certificate verification job (see
    /// [`SslContextBuilder::set_async_default_verify`]) is outstanding for this `Ssl`. Only such
    /// a job's completion will wake this `Ssl`'s task out of
    /// [`ErrorCode::WANT_CERTIFICATE_VERIFY`](super::ErrorCode::WANT_CERTIFICATE_VERIFY); a
    /// synchronous custom verify callback that itself returns
    /// [`SslVerifyError::Retry`](super::SslVerifyError::Retry) needs its own drive/retry
    /// mechanism instead, since nothing will wake this `Ssl` for it.
    pub fn has_pending_certificate_verification(&self) -> bool {
        self.ex_data(*PENDING_INDEX).is_some_and(Option::is_some)
    }
}

/// Whether the peer's certificate chain of `ssl` consists of the very certificates of `chain`.
fn is_peer_chain(ssl: &SslRef, chain: &[X509]) -> bool {
    let current = unsafe { ffi::SSL_get_peer_full_cert_chain(ssl.as_ptr()) };
    if current.is_null() {
        return false;
    }
    let current = unsafe { StackRef::<X509>::from_ptr(current) };
    current.len() == chain.len()
        && current
            .iter()
            .zip(chain)
            .all(|(a, b)| ptr::eq(a.as_ptr(), b.as_ptr()))
}

/// A verification the handshake waits for, kept in the `Ssl`'s ex data.
struct Pending {
    task: Arc<Task>,
    /// The peer's certificates the job verifies.
    chain: Vec<X509>,
}

/// The state a job shares with the handshake.
struct Task(Mutex<State>);

enum State {
    /// The job has not finished; the waker wakes the handshake when it does.
    Running(Option<Waker>),
    Done(Outcome),
    Taken,
}

impl Task {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stores the outcome of the job, unless it has one already, and wakes the handshake.
    fn complete(&self, outcome: Outcome) {
        let waker = {
            let mut state = self.lock();
            let State::Running(waker) = &mut *state else {
                return;
            };
            let waker = waker.take();
            *state = State::Done(outcome);
            waker
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Takes the outcome of the job if it has finished, or else keeps `waker` (if any) to wake
    /// the handshake.
    fn poll(&self, waker: Option<Waker>) -> Option<Outcome> {
        let mut state = self.lock();
        match mem::replace(&mut *state, State::Taken) {
            State::Done(outcome) => Some(outcome),
            State::Running(previous) => {
                *state = State::Running(waker.or(previous));
                None
            }
            State::Taken => None,
        }
    }
}

enum Outcome {
    /// `X509_verify_cert` ran: whether it succeeded and the verify result it left.
    Verified { ok: bool, error: c_int },
    /// The job was dropped without finishing.
    Dropped,
}

struct Job {
    verification: Option<Verification>,
    task: Arc<Task>,
}

impl Job {
    fn run(mut self) {
        if let Some(verification) = self.verification.take() {
            self.task.complete(verification.run());
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // Does nothing if the job has finished.
        self.task.complete(Outcome::Dropped);
    }
}

/// Keeps what a context from [`ffi::SSL_new_peer_chain_verify_ctx`] borrows from its `Ssl` (the
/// verify store) alive for as long as the context itself, independent of the `Ssl` (and anything
/// it owns, e.g. a per-connection verify store): [`Verification::run`] uses the context from
/// another thread, possibly after the `Ssl` is gone, and with it a `Pending`'s own copy of the
/// chain, kept in the `Ssl`'s ex data.
static STORE_KEPT_ALIVE_INDEX: LazyLock<Index<X509StoreContext, X509Store>> =
    LazyLock::new(|| X509StoreContext::new_ex_index().unwrap());

/// Keeps an independently owned untrusted-chain stack alive for as long as the context: unlike
/// the store (a single refcounted object `ctx`'s own borrowed pointer already keeps reachable),
/// the chain [`ffi::SSL_new_peer_chain_verify_ctx`] borrows is the `STACK_OF(X509)` *container*
/// the peer's `SSL_SESSION` owns, not just its certificates. Up-referencing each certificate
/// (as [`Verification::new`] already does for its own returned `Vec<X509>`) does not stop that
/// container itself from being freed if the session is. `X509_STORE_CTX_set_chain` replaces it
/// with this one, built fresh from the same, now up-referenced, certificates.
static CHAIN_KEPT_ALIVE_INDEX: LazyLock<Index<X509StoreContext, Stack<X509>>> =
    LazyLock::new(|| X509StoreContext::new_ex_index().unwrap());

/// An `X509_STORE_CTX` set up like the one BoringSSL's built-in verification uses. It owns the
/// store and the certificates, so it can outlive the handshake and move to another thread.
struct Verification(X509StoreContext);

impl Verification {
    /// Sets up the verification of `ssl`'s peer chain via [`ffi::SSL_new_peer_chain_verify_ctx`],
    /// which shares its setup with BoringSSL's own `ssl_crypto_x509_session_verify_cert_chain` (so
    /// a future change to the built-in's setup cannot silently diverge from this), and returns
    /// `NULL` if a verify callback is set anywhere that could use `ssl` and so cannot run outside
    /// the handshake. Returns the verification and the certificates it verifies.
    fn new(ssl: &SslRef) -> Result<(Self, Vec<X509>), SslAlert> {
        let internal_error = |_| SslAlert::INTERNAL_ERROR;
        unsafe {
            let ctx = ffi::SSL_new_peer_chain_verify_ctx(ssl.as_ptr());
            if ctx.is_null() {
                return Err(SslAlert::INTERNAL_ERROR);
            }
            let mut ctx = X509StoreContext::from_ptr(ctx);

            let store =
                X509StoreRef::from_ptr(ffi::X509_STORE_CTX_get0_store(ctx.as_ptr())).to_owned();
            let untrusted = ffi::X509_STORE_CTX_get0_untrusted(ctx.as_ptr());
            let chain: Vec<X509> = StackRef::<X509>::from_ptr(untrusted)
                .iter()
                .map(ToOwned::to_owned)
                .collect();
            if chain.is_empty() {
                return Err(SslAlert::INTERNAL_ERROR);
            }

            // The context's own store pointer still borrows ssl's; keep our own owned reference
            // to the same object alive for as long as the context does.
            ctx.set_ex_data(*STORE_KEPT_ALIVE_INDEX, store);

            // Unlike the store, the untrusted chain SSL_new_peer_chain_verify_ctx set is the
            // STACK_OF(X509) container the peer's SSL_SESSION owns, not just its certificates:
            // up-referencing the certificates (which `chain` above already does) does not stop
            // that container itself from being freed if the session is. Replace it with a fresh
            // one, built from the same, now up-referenced, certificates.
            let mut owned_chain = Stack::new().map_err(internal_error)?;
            for cert in &chain {
                owned_chain.push(cert.clone()).map_err(internal_error)?;
            }
            ffi::X509_STORE_CTX_set_chain(ctx.as_ptr(), owned_chain.as_ptr());
            ctx.set_ex_data(*CHAIN_KEPT_ALIVE_INDEX, owned_chain);

            Ok((Verification(ctx), chain))
        }
    }

    fn run(self) -> Outcome {
        unsafe {
            let ok = ffi::X509_verify_cert(self.0.as_ptr()) > 0;
            let error = ffi::X509_STORE_CTX_get_error(self.0.as_ptr());
            // Do not leave errors it queued on this thread for unrelated work to find.
            ffi::ERR_clear_error();
            Outcome::Verified { ok, error }
        }
    }
}

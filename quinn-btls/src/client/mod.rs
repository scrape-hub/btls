use crate::alpn::AlpnProtocols;
use crate::bffi_ext::QuicSslContext;
use crate::error::{map_result, Result};
use crate::session_state::{SessionState, QUIC_METHOD};
use crate::version::QuicVersion;
use crate::{session_cache_key, Entry, QuicSsl, QuicSslSession, SessionCache, SimpleCache};
use btls::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslRef, SslSession, SslVersion};
use btls_sys as bffi;
use bytes::{Bytes, BytesMut};
use foreign_types_shared::ForeignType;
use quinn_proto::{
    crypto, transport_parameters::TransportParameters, ConnectError, ConnectionId, Side,
    TransportError,
};
use std::any::Any;
use std::ffi::c_int;
use std::io::Cursor;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::sync::LazyLock;
use std::task::{Poll, Waker};
use tracing::{trace, warn};

/// A callback that configures the [SslRef] of a new client connection, see
/// [Config::set_configure_connection_callback]. The [TransportParameters]
/// are the real (inner) ones this connection already offers, for a callback
/// that also needs [SslRef::set_quic_transport_params_outer]: a reduced
/// set for a ClientHelloOuter is usually filtered from these, not built
/// separately.
type ConfigureConnection =
    dyn Fn(&mut SslRef, &str, &TransportParameters) -> Result<()> + Send + Sync;

/// Configuration for a client-side QUIC. Wraps around a BoringSSL [SslContext].
///
/// Certificate verification can run on another thread: set it up with
/// [SslContextBuilder::set_async_default_verify] on the builder for [Config::from_builder], or on
/// each connection's [SslRef] in [Config::set_configure_connection_callback]. While it runs, the
/// session has no handshake data to send, so quinn only acknowledges the server's packets, and
/// [crypto::Session::poll_handshake] is `Pending`. Once it is done, the verification wakes the
/// connection, and the Finished goes out at once.
///
/// QUIC versions 1 and 2 (RFC 9369) are supported, and a session follows a server that switches
/// the connection to the other one (compatible version negotiation, RFC 9368) through
/// [crypto::Session::set_version]. Session tickets are kept per version, see
/// [session_cache_key](crate::session_cache_key).
pub struct Config {
    ctx: SslContext,
    session_cache: Arc<dyn SessionCache>,
    configure_connection: Option<Box<ConfigureConnection>>,
}

impl Config {
    pub fn new() -> Result<Self> {
        let mut builder = SslContextBuilder::new(SslMethod::tls())?;

        // QUIC requires TLS 1.3.
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        builder.set_default_verify_paths()?;

        let mut config = Self::from_builder(builder)?;
        // Only this constructor's own, freshly-built context defaults to
        // verifying the server; from_builder leaves whatever the caller's
        // builder already configured alone.
        config.ctx.verify_peer(true);
        Ok(config)
    }

    /// Create a QUIC client config from a pre-configured [SslContextBuilder].
    ///
    /// The caller is responsible for setting TLS parameters on the builder
    /// (cipher list, curves, sigalgs, certificate verification, cert compression, etc.)
    /// before passing it here. This constructor enforces TLS 1.3 and applies
    /// QUIC-specific settings (ALPN, session cache, QUIC method callbacks, early data).
    ///
    /// This is useful when custom root certificates are needed, e.g. on Windows, where BoringSSL
    /// finds no system CA store, or when each configuration needs its own TLS parameters.
    pub fn from_builder(mut builder: SslContextBuilder) -> Result<Self> {
        // QUIC requires TLS 1.3.
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        // We build the context early, since we are not allowed to further mutate the context
        // in start_session.
        let mut ctx = builder.build();

        // By default, enable early data (used for 0-RTT).
        ctx.enable_early_data(true);

        // Set the default ALPN protocols offered by the client. QUIC requires ALPN be configured
        // (see <https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1>).
        ctx.set_alpn_protos(&AlpnProtocols::default().encode())?;

        // Configure session caching.
        ctx.set_session_cache_mode(bffi::SSL_SESS_CACHE_CLIENT | bffi::SSL_SESS_CACHE_NO_INTERNAL);
        ctx.set_new_session_callback(Some(Session::new_session_callback));

        // Set callbacks for the SessionState.
        ctx.set_quic_method(&QUIC_METHOD)?;
        ctx.set_info_callback(Some(SessionState::info_callback));

        Ok(Self {
            ctx,
            session_cache: Arc::new(SimpleCache::new(256)),
            configure_connection: None,
        })
    }

    /// Returns the underlying [SslContext] backing all created sessions.
    pub fn ctx(&self) -> &SslContext {
        &self.ctx
    }

    /// Returns the underlying [SslContext] backing all created sessions. Wherever possible use
    /// the provided methods to modify settings rather than accessing this directly.
    ///
    /// Care should be taken to avoid overriding required behavior. In particular, this
    /// configuration will set callbacks for QUIC events, alpn selection, server name,
    /// as well as info and key logging.
    pub fn ctx_mut(&mut self) -> &mut SslContext {
        &mut self.ctx
    }

    /// Sets whether or not the peer certificate should be verified. If `true`, any error
    /// during verification will be fatal. If not called, verification of the server is
    /// enabled by default.
    pub fn verify_peer(&mut self, verify: bool) {
        self.ctx.verify_peer(verify)
    }

    /// Gets the [SessionCache] used to cache all client sessions.
    pub fn get_session_cache(&self) -> Arc<dyn SessionCache> {
        self.session_cache.clone()
    }

    /// Sets the [SessionCache] to be shared by all created client sessions.
    pub fn set_session_cache(&mut self, session_cache: Arc<dyn SessionCache>) {
        self.session_cache = session_cache;
    }

    /// Sets the ALPN protocols supported by the client. QUIC requires that
    /// ALPN be used (see <https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1>).
    /// By default, the client will offer "h3".
    pub fn set_alpn(&mut self, alpn_protocols: &[Vec<u8>]) -> Result<()> {
        self.ctx
            .set_alpn_protos(&AlpnProtocols::from(alpn_protocols).encode())?;
        Ok(())
    }

    /// Sets a callback that configures the [SslRef] of every new connection before its
    /// handshake starts. It receives the server name the connection is opened for and the real
    /// (inner) [TransportParameters] this connection already offers, for
    /// [SslRef::set_quic_transport_params_outer], which a reduced ClientHelloOuter set is usually
    /// filtered from, not built separately.
    ///
    /// This is where settings go that BoringSSL keeps per connection rather than per context,
    /// such as ECH ([SslRef::set_enable_ech_grease], [SslRef::set_ech_config_list]), ALPS
    /// ([SslRef::add_application_settings]) or the key shares
    /// ([SslRef::set_client_key_shares]). The callback runs after the server name, the hostname
    /// to verify, the transport parameters and a session from the [SessionCache] have been set,
    /// so [SslRef::session] tells whether the connection got a session to offer. BoringSSL still
    /// drops it when the handshake starts if it cannot offer it, e.g. because it has expired;
    /// then the ClientHello offers none. Sessions themselves are managed through the
    /// [SessionCache], which also keeps the transport parameters 0-RTT needs. An error aborts the
    /// connection attempt.
    pub fn set_configure_connection_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, &str, &TransportParameters) -> Result<()> + Send + Sync + 'static,
    {
        self.configure_connection = Some(Box::new(callback));
    }
}

impl crypto::ClientConfig for Config {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> StdResult<Box<dyn crypto::Session>, ConnectError> {
        let version = QuicVersion::parse(version)?;

        Ok(Session::new(self, version, server_name, params, None)?)
    }
}

/// A [`Config`] plus data specific to one connection attempt, such as an ECH config list looked
/// up per host. Wraps the same shared [`Config`] (no new [`SslContext`](btls::ssl::SslContext)
/// is built) and runs `configure` for this connection's [`SslRef`] right after the shared
/// [`Config::set_configure_connection_callback`], if any, at the same point in the handshake (see
/// that method's doc).
///
/// Unlike [`Config::set_configure_connection_callback`], which is set once and reused for every
/// connection the shared [`Config`] starts, `configure` here is specific to the one
/// [`PerConnectionConfig`] it was built with: a caller building a fresh one per connection
/// attempt (as [`quinn::Endpoint::connect_with`] takes a fresh `Arc<dyn ClientConfig>` per call
/// already) can pass per-connection data without keeping it in shared, per-client state that
/// unrelated or overlapping connection attempts could race on or overwrite.
pub struct PerConnectionConfig {
    shared: Arc<Config>,
    configure: Box<ConfigureConnection>,
}

impl PerConnectionConfig {
    pub fn new<F>(shared: Arc<Config>, configure: F) -> Self
    where
        F: Fn(&mut SslRef, &str, &TransportParameters) -> Result<()> + Send + Sync + 'static,
    {
        Self {
            shared,
            configure: Box::new(configure),
        }
    }
}

impl crypto::ClientConfig for PerConnectionConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> StdResult<Box<dyn crypto::Session>, ConnectError> {
        let version = QuicVersion::parse(version)?;

        Ok(Session::new(
            self.shared.clone(),
            version,
            server_name,
            params,
            Some(&*self.configure),
        )?)
    }
}

static SESSION_INDEX: LazyLock<c_int> = LazyLock::new(|| unsafe {
    bffi::SSL_get_ex_new_index(0, std::ptr::null_mut(), std::ptr::null_mut(), None, None)
});

/// The [crypto::Session] implementation for BoringSSL.
struct Session {
    state: Box<SessionState>,
    server_name: String,
    session_cache: Arc<dyn SessionCache>,
    zero_rtt_peer_params: Option<TransportParameters>,
    handshake_data_available: bool,
    handshake_data_sent: bool,
}

impl Session {
    /// `extra_configure`, when given, runs on this connection's `Ssl` right after `cfg`'s own
    /// shared [`Config::set_configure_connection_callback`], if any; see [`PerConnectionConfig`].
    fn new(
        cfg: Arc<Config>,
        version: QuicVersion,
        server_name: &str,
        params: &TransportParameters,
        extra_configure: Option<&ConfigureConnection>,
    ) -> Result<Box<Self>> {
        let session_cache = cfg.session_cache.clone();
        let mut ssl = Ssl::new(&cfg.ctx).unwrap();

        // Configure the TLS extension based on the QUIC version used.
        ssl.set_quic_use_legacy_codepoint(version.uses_legacy_extension());

        // Configure the SSL to be a client.
        ssl.set_connect_state();

        // Configure verification for the server hostname.
        ssl.set_verify_hostname(server_name)
            .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?;

        // Set the SNI hostname.
        // TODO: should we validate the hostname?
        ssl.set_hostname(server_name)
            .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?;

        // Set the transport parameters.
        ssl.set_quic_transport_params(&encode_params(params))?;

        // If we have a cached session, offer it. A TLS 1.3 ticket is used only once, so take it
        // out of the cache; this connection stores the tickets the server sends it. BoringSSL
        // offers the session as a PSK and, if the ticket allows early data, also attempts 0-RTT.
        // It drops a session it cannot offer, e.g. an expired one, when the handshake starts;
        // that one is gone from the cache too, but could not have been used later either.
        // Only a session of a connection of this QUIC version (RFC 9369, section 5).
        let mut zero_rtt_peer_params = None;
        if let Some(entry) = session_cache.take(session_cache_key(server_name, version.label())) {
            match Entry::decode(ssl.ssl_context(), entry) {
                Ok(entry) => {
                    zero_rtt_peer_params = Some(entry.params);
                    match unsafe { ssl.set_session(entry.session.as_ref()) } {
                        Ok(()) => {
                            if entry.session.early_data_capable() {
                                trace!(
                                    "attempting resumption (0-RTT) for server: {}.",
                                    server_name
                                );
                            } else {
                                trace!(
                                    "attempting resumption (1-RTT) for server: {}. The ticket \
                                     does not allow early data.",
                                    server_name
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                "failed setting cached session for server {}: {:?}",
                                server_name, e
                            )
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "failed decoding session entry for server {}: {:?}",
                        server_name, e
                    )
                }
            }
        } else {
            trace!(
                "no cached session found for server: {}. Will continue with 1-RTT.",
                server_name
            );
        }

        if let Some(configure) = &cfg.configure_connection {
            if let Err(e) = configure(&mut ssl, server_name, params) {
                warn!(
                    "failed configuring the connection to server {}: {:?}",
                    server_name, e
                );
                return Err(e);
            }
        }
        if let Some(configure) = extra_configure {
            if let Err(e) = configure(&mut ssl, server_name, params) {
                warn!(
                    "failed configuring the connection to server {}: {:?}",
                    server_name, e
                );
                return Err(e);
            }
        }

        let mut session = Box::new(Self {
            state: SessionState::new(ssl, Side::Client, version)?,
            server_name: server_name.to_owned(),
            session_cache,
            zero_rtt_peer_params,
            handshake_data_available: false,
            handshake_data_sent: false,
        });

        // Register the instance in SSL ex_data. This allows the static callbacks to
        // reference the instance.
        unsafe {
            map_result(bffi::SSL_set_ex_data(
                session.state.ssl.as_ptr(),
                *SESSION_INDEX,
                &mut *session as *mut Self as *mut _,
            ))?;
        }

        // Start the handshake in order to emit the Client Hello on the first
        // call to write_handshake.
        session.state.advance_handshake()?;

        Ok(session)
    }

    /// Handler for the rejection of a 0-RTT attempt. Will continue with 1-RTT.
    fn on_zero_rtt_rejected(&mut self) {
        trace!(
            "0-RTT handshake attempted but was rejected by the server: {}",
            Ssl::early_data_reason_string(self.state.ssl.get_early_data_reason())
        );

        self.zero_rtt_peer_params = None;

        // The ticket was taken out of the cache when the connection started. Leave the cache
        // alone: an entry there now came from another connection.

        // Now retry advancing the handshake, this time in 1-RTT mode.
        if let Err(e) = self.state.advance_handshake() {
            warn!("failed advancing 1-RTT handshake: {:?}", e)
        }
    }

    /// Client-side only callback from BoringSSL to allow caching of a new session.
    ///
    /// Every ticket is cached, whether or not it allows early data: a ticket without early data
    /// still resumes the session with a PSK. BoringSSL attempts 0-RTT only with a ticket that
    /// allows it ([QuicSslSession::early_data_capable]), and without 0-RTT keys quinn's
    /// `Connecting::into_0rtt` fails and the handshake continues in 1-RTT.
    fn on_new_session(&mut self, session: SslSession) {
        // Get the server transport parameters.
        let params = match self.state.ssl.get_peer_quic_transport_params() {
            Some(params) => {
                match TransportParameters::read(Side::Client, &mut Cursor::new(&params)) {
                    Ok(params) => params,
                    Err(e) => {
                        warn!("failed parsing server transport parameters: {:?}", e);
                        return;
                    }
                }
            }
            None => {
                warn!("failed caching session: server transport parameters are not available");
                return;
            }
        };

        // Encode the session cache entry, including both the session and the server params.
        let entry = Entry { session, params };
        match entry.encode() {
            Ok(value) => {
                // Under the version of the connection, the negotiated one if the server switched
                // versions (RFC 9369, section 5).
                let key = session_cache_key(&self.server_name, self.state.version.label());
                self.session_cache.put(key, value)
            }
            Err(e) => {
                warn!("failed caching session: unable to encode entry: {:?}", e);
            }
        }
    }

    /// Called by the static callbacks to retrieve the instance pointer.
    #[inline]
    fn get_instance(ssl: *const bffi::SSL) -> &'static mut Session {
        unsafe {
            let data = bffi::SSL_get_ex_data(ssl, *SESSION_INDEX);
            if data.is_null() {
                panic!("BUG: Session instance missing")
            }
            &mut *(data as *mut Session)
        }
    }

    /// Raw callback from BoringSSL.
    extern "C" fn new_session_callback(
        ssl: *mut bffi::SSL,
        session: *mut bffi::SSL_SESSION,
    ) -> c_int {
        let inst = Self::get_instance(ssl);
        let session = unsafe { SslSession::from_ptr(session) };
        inst.on_new_session(session);

        // Return 1 to indicate we've taken ownership of the session.
        1
    }
}

impl crypto::Session for Session {
    fn initial_keys(&self, dcid: &ConnectionId, side: Side) -> crypto::Keys {
        self.state.initial_keys(dcid, side)
    }

    fn set_version(&mut self, version: u32) -> StdResult<(), crypto::UnsupportedVersion> {
        self.state.set_version(QuicVersion::parse(version)?)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.state.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.state.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        self.state.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        Some(self.state.ssl.early_data_accepted())
    }

    fn is_handshaking(&self) -> bool {
        self.state.is_handshaking()
    }

    fn read_handshake(&mut self, plaintext: &[u8]) -> StdResult<bool, TransportError> {
        self.state.read_handshake(plaintext)?;

        if self.state.early_data_rejected {
            self.on_zero_rtt_rejected();
        }

        // Only indicate that handshake data is available once.
        // On the client side there is no ALPN callback, so we need to manually check
        // if the ALPN protocol has been selected.
        if !self.handshake_data_sent {
            if self.state.ssl.selected_alpn_protocol().is_some() {
                self.handshake_data_available = true;
            }

            if self.handshake_data_available {
                self.handshake_data_sent = true;
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn poll_handshake(&mut self, waker: &Waker) -> Poll<StdResult<(), TransportError>> {
        self.state.poll_handshake(waker)
    }

    fn transport_parameters(&self) -> StdResult<Option<TransportParameters>, TransportError> {
        match self.state.transport_parameters()? {
            Some(params) => Ok(Some(params)),
            None => {
                if self.state.ssl.in_early_data() {
                    Ok(self.zero_rtt_peer_params)
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        self.state.write_handshake(buf)
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        self.state.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.state.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> StdResult<(), crypto::ExportKeyingMaterialError> {
        self.state.export_keying_material(output, label, context)
    }
}

fn encode_params(params: &TransportParameters) -> Bytes {
    let mut out = BytesMut::with_capacity(128);
    params.write(&mut out);
    out.freeze()
}

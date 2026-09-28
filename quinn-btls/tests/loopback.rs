//! Runs a quinn-btls client against a quinn-btls server over loopback.

use std::collections::HashSet;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use btls::hash::MessageDigest;
use btls::hmac::Hmac;
use btls::hpke::{HpkeAead, HpkeKey};
use btls::pkey::{PKey, Private};
use btls::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, ExtensionType, KeyShare,
    SslContextBuilder, SslEchKeys, SslMethod, SslSignatureAlgorithm, SslVerifyMode, VerifyJob,
};
use btls::symm::{decrypt_aead, encrypt, Cipher};
use btls::x509::X509;
use btls_sys as bffi;
use bytes::Bytes;
use quinn_btls::{
    helpers, session_cache_key, ClientConfig, Entry, HandshakeData, PerConnectionConfig,
    QuicSslContext, QuicSslSession, ServerConfig, SessionCache, SimpleCache,
};
use quinn_proto::QUIC_VERSION_2;

const SERVER_NAME: &str = "localhost";

fn self_signed_certificate() -> (X509, PKey<Private>) {
    let certified = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
    let cert = X509::from_der(certified.cert.der()).unwrap();
    let key = PKey::private_key_from_pkcs8(&certified.signing_key.serialize_der()).unwrap();
    (cert, key)
}

fn server_endpoint(cert: X509, key: PKey<Private>, crypto: ServerConfig) -> quinn::Endpoint {
    let mut crypto = crypto;
    crypto.ctx_mut().set_certificate(cert).unwrap();
    crypto.ctx_mut().set_private_key(key).unwrap();
    let config = helpers::server_config(Arc::new(crypto)).unwrap();
    helpers::server_endpoint(config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap()
}

/// A client context that trusts `cert`, for `ClientConfig::from_builder`. `from_builder` leaves
/// verification as the builder configures it, so this turns it on itself, the way a real caller
/// would.
fn client_builder(cert: &X509) -> SslContextBuilder {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
    builder.cert_store_mut().add_cert(cert).unwrap();
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    builder
}

fn client_endpoint(crypto: ClientConfig) -> quinn::Endpoint {
    let mut endpoint = helpers::client_endpoint((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    endpoint
}

fn handshake_data(conn: &quinn::Connection) -> HandshakeData {
    *conn
        .handshake_data()
        .unwrap()
        .downcast::<HandshakeData>()
        .unwrap()
}

/// Accepts `count` connections, echoes one bidirectional stream on each and returns the
/// handshake data the server saw, in the order the connections arrived. Connections are
/// handled concurrently.
async fn run_echo_server(endpoint: quinn::Endpoint, count: usize) -> Vec<HandshakeData> {
    let mut connections = Vec::new();
    for _ in 0..count {
        let incoming = endpoint.accept().await.unwrap();
        connections.push(tokio::spawn(async move {
            let conn = incoming.await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let request = recv.read_to_end(1024).await.unwrap();
            send.write_all(&request).await.unwrap();
            send.finish().unwrap();
            let seen = handshake_data(&conn);
            conn.closed().await;
            seen
        }));
    }
    let mut seen = Vec::new();
    for connection in connections {
        seen.push(connection.await.unwrap());
    }
    seen
}

/// A [SimpleCache] that counts the sessions stored in it.
struct CountingCache {
    cache: SimpleCache,
    stored: AtomicUsize,
}

impl CountingCache {
    fn new() -> Arc<Self> {
        Arc::new(CountingCache {
            cache: SimpleCache::new(16),
            stored: AtomicUsize::new(0),
        })
    }

    /// Waits until `count` sessions have been stored in all.
    async fn wait_for(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.stored.load(Ordering::SeqCst) < count {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("no session ticket received");
    }
}

impl SessionCache for CountingCache {
    fn put(&self, key: Bytes, value: Bytes) {
        self.cache.put(key, value);
        self.stored.fetch_add(1, Ordering::SeqCst);
    }

    fn get(&self, key: Bytes) -> Option<Bytes> {
        self.cache.get(key)
    }

    fn take(&self, key: Bytes) -> Option<Bytes> {
        self.cache.take(key)
    }

    fn remove(&self, key: Bytes) {
        self.cache.remove(key)
    }

    fn clear(&self) {
        self.cache.clear()
    }
}

async fn echo(conn: &quinn::Connection, request: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(request).await.unwrap();
    send.finish().unwrap();
    recv.read_to_end(1024).await.unwrap()
}

#[tokio::test]
async fn handshake_stream_and_resumption() {
    let (cert, key) = self_signed_certificate();
    let server = server_endpoint(cert.clone(), key, ServerConfig::new().unwrap());
    let server_addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(run_echo_server(server, 2));

    let crypto = ClientConfig::from_builder(client_builder(&cert)).unwrap();
    let session_cache = crypto.get_session_cache();
    let client = client_endpoint(crypto);

    let mut client_seen = Vec::new();
    for request in [&b"first"[..], b"second"] {
        let conn = client.connect(server_addr, SERVER_NAME).unwrap();
        let conn = tokio::time::timeout(Duration::from_secs(10), conn)
            .await
            .expect("handshake timed out")
            .unwrap();

        let response = tokio::time::timeout(Duration::from_secs(10), echo(&conn, request))
            .await
            .expect("echo timed out");
        assert_eq!(response, request);

        // The server sends its session tickets right after the handshake; wait until the client
        // has stored one before connecting again.
        tokio::time::timeout(Duration::from_secs(10), async {
            while session_cache.get(Bytes::from(SERVER_NAME)).is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("no session ticket received");

        client_seen.push(handshake_data(&conn));
        conn.close(0u32.into(), b"done");
    }

    let server_seen = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server timed out")
        .unwrap();

    for data in client_seen.iter().chain(&server_seen) {
        assert_eq!(data.protocol.as_deref(), Some(&b"h3"[..]));
    }
    for data in &server_seen {
        assert_eq!(data.server_name.as_deref(), Some(SERVER_NAME));
    }

    let client_reused: Vec<bool> = client_seen.iter().map(|d| d.session_reused).collect();
    let server_reused: Vec<bool> = server_seen.iter().map(|d| d.session_reused).collect();
    assert_eq!(client_reused, [false, true], "client session_reused");
    assert_eq!(server_reused, [false, true], "server session_reused");

    client.wait_idle().await;
}

static SIGNATURE_ALGORITHMS: Mutex<Option<Vec<u8>>> = Mutex::new(None);

extern "C" fn record_signature_algorithms(
    client_hello: *const bffi::SSL_CLIENT_HELLO,
) -> bffi::ssl_select_cert_result_t {
    let mut data = ptr::null();
    let mut len = 0;
    let found = unsafe {
        bffi::SSL_early_callback_ctx_extension_get(
            client_hello,
            bffi::TLSEXT_TYPE_signature_algorithms as u16,
            &mut data,
            &mut len,
        )
    };
    if found == 1 {
        let ext = unsafe { slice::from_raw_parts(data, len) };
        *SIGNATURE_ALGORITHMS.lock().unwrap() = Some(ext.to_vec());
    }
    bffi::ssl_select_cert_result_t::ssl_select_cert_success
}

#[tokio::test]
async fn grease_sigalgs_in_quic_client_hello() {
    let (cert, key) = self_signed_certificate();
    let mut server_crypto = ServerConfig::new().unwrap();
    server_crypto
        .ctx_mut()
        .set_select_certificate_cb(Some(record_signature_algorithms));
    let server = server_endpoint(cert.clone(), key, server_crypto);
    let server_addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(run_echo_server(server, 1));

    let mut builder = client_builder(&cert);
    builder.set_grease_sigalgs_enabled(true);
    let client = client_endpoint(ClientConfig::from_builder(builder).unwrap());

    let conn = client.connect(server_addr, SERVER_NAME).unwrap();
    let conn = tokio::time::timeout(Duration::from_secs(10), conn)
        .await
        .expect("handshake timed out")
        .unwrap();
    assert_eq!(echo(&conn, b"grease").await, b"grease");
    conn.close(0u32.into(), b"done");
    server_task.await.unwrap();

    let ext = SIGNATURE_ALGORITHMS
        .lock()
        .unwrap()
        .take()
        .expect("no signature_algorithms extension");
    let first = u16::from_be_bytes([ext[2], ext[3]]);
    assert!(
        first & 0x0f0f == 0x0a0a && first >> 8 == first & 0xff,
        "first signature algorithm {first:#06x} is not a GREASE value"
    );

    client.wait_idle().await;
}

const TLSEXT_SERVER_NAME: u16 = 0x0000;
const TLSEXT_STATUS_REQUEST: u16 = 0x0005;
const TLSEXT_SUPPORTED_GROUPS: u16 = 0x000a;
const TLSEXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const TLSEXT_ALPN: u16 = 0x0010;
const TLSEXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const TLSEXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const TLSEXT_RECORD_SIZE_LIMIT: u16 = 0x001c;
const TLSEXT_DELEGATED_CREDENTIAL: u16 = 0x0022;
const TLSEXT_PRE_SHARED_KEY: u16 = 0x0029;
const TLSEXT_EARLY_DATA: u16 = 0x002a;
const TLSEXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const TLSEXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const TLSEXT_KEY_SHARE: u16 = 0x0033;
const TLSEXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
const TLSEXT_APPLICATION_SETTINGS: u16 = 0x44cd;
const TLSEXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const TLSEXT_RENEGOTIATE: u16 = 0xff01;

/// Raw ClientHello bodies the server saw, one slot per test so that tests running in parallel
/// keep theirs apart.
static CLIENT_HELLOS: [Mutex<Vec<Vec<u8>>>; 4] = [const { Mutex::new(Vec::new()) }; 4];

extern "C" fn record_client_hello<const SLOT: usize>(
    client_hello: *const bffi::SSL_CLIENT_HELLO,
) -> bffi::ssl_select_cert_result_t {
    let client_hello = unsafe { &*client_hello };
    let body =
        unsafe { slice::from_raw_parts(client_hello.client_hello, client_hello.client_hello_len) };
    CLIENT_HELLOS[SLOT].lock().unwrap().push(body.to_vec());
    bffi::ssl_select_cert_result_t::ssl_select_cert_success
}

struct ClientHello {
    cipher_suites: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl ClientHello {
    fn parse(body: &[u8]) -> Self {
        let mut body = Reader(body);
        body.take(2 + 32); // legacy_version, random
        let len = body.u8();
        body.take(len); // legacy_session_id
        let len = body.u16();
        let cipher_suites = u16_list(body.take(len));
        let len = body.u8();
        body.take(len); // legacy_compression_methods
        let len = body.u16();
        let mut exts = Reader(body.take(len));
        let mut extensions = Vec::new();
        while !exts.0.is_empty() {
            let ext_type = exts.u16() as u16;
            let len = exts.u16();
            extensions.push((ext_type, exts.take(len).to_vec()));
        }
        ClientHello {
            cipher_suites,
            extensions,
        }
    }

    fn extension_types(&self) -> Vec<u16> {
        self.extensions.iter().map(|(t, _)| *t).collect()
    }

    fn extension_set(&self) -> HashSet<u16> {
        self.extension_types().into_iter().collect()
    }

    fn extension(&self, ext_type: u16) -> &[u8] {
        self.extensions
            .iter()
            .find(|(t, _)| *t == ext_type)
            .map(|(_, data)| &data[..])
            .unwrap_or_else(|| panic!("extension {ext_type:#06x} missing"))
    }

    /// A list with a 16-bit length prefix of 16-bit values.
    fn u16_list(&self, ext_type: u16) -> Vec<u16> {
        u16_list(&self.extension(ext_type)[2..])
    }

    fn key_share_groups(&self) -> Vec<u16> {
        let mut shares = Reader(&self.extension(TLSEXT_KEY_SHARE)[2..]);
        let mut groups = Vec::new();
        while !shares.0.is_empty() {
            groups.push(shares.u16() as u16);
            let len = shares.u16();
            shares.take(len);
        }
        groups
    }

    /// The AEAD and payload length of an outer encrypted_client_hello extension.
    fn ech_aead_and_payload_len(&self) -> (u16, usize) {
        let mut ech = Reader(self.extension(TLSEXT_ENCRYPTED_CLIENT_HELLO));
        assert_eq!(ech.u8(), 0, "not an outer ECH extension");
        assert_eq!(ech.u16(), 1, "KDF is not HKDF-SHA256");
        let aead = ech.u16() as u16;
        ech.u8(); // config_id
        let len = ech.u16();
        assert_eq!(ech.take(len).len(), 32, "enc");
        let len = ech.u16();
        (aead, ech.take(len).len())
    }

    fn has_grease(&self) -> bool {
        let is_grease = |v: &u16| v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff;
        self.cipher_suites.iter().any(is_grease)
            || self.extension_types().iter().any(is_grease)
            || self.u16_list(TLSEXT_SUPPORTED_GROUPS).iter().any(is_grease)
            || self
                .u16_list(TLSEXT_SIGNATURE_ALGORITHMS)
                .iter()
                .any(is_grease)
            || self.key_share_groups().iter().any(is_grease)
    }
}

fn u16_list(bytes: &[u8]) -> Vec<u16> {
    assert_eq!(bytes.len() % 2, 0);
    bytes
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        head
    }

    fn u8(&mut self) -> usize {
        self.take(1)[0] as usize
    }

    fn u16(&mut self) -> usize {
        let b = self.take(2);
        u16::from_be_bytes([b[0], b[1]]) as usize
    }
}

/// A certificate compression algorithm for the client to announce. The server never compresses
/// its certificate in these tests.
#[derive(Debug)]
struct Announced<const ALGORITHM: u16>;

impl<const ALGORITHM: u16> CertificateCompressor for Announced<ALGORITHM> {
    fn compress(&self, _: &[u8], _: &mut dyn Write) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn decompress(&self, _: &[u8], _: &mut dyn Write) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        match ALGORITHM {
            1 => CertificateCompressionAlgorithm::ZLIB,
            2 => CertificateCompressionAlgorithm::BROTLI,
            3 => CertificateCompressionAlgorithm::ZSTD,
            _ => unreachable!(),
        }
    }
}

fn sigalgs(values: &[u16]) -> Vec<SslSignatureAlgorithm> {
    values.iter().copied().map(Into::into).collect()
}

/// Connects twice to a server that records the ClientHellos in `CLIENT_HELLOS[SLOT]`, the
/// second time with the session ticket of the first connection. Returns the ClientHellos and
/// whether each connection resumed.
async fn record_client_hellos<const SLOT: usize>(
    cert: X509,
    key: PKey<Private>,
    crypto: ClientConfig,
) -> (Vec<ClientHello>, Vec<bool>) {
    let mut server_crypto = ServerConfig::new().unwrap();
    server_crypto
        .ctx_mut()
        .set_select_certificate_cb(Some(record_client_hello::<SLOT>));
    let server = server_endpoint(cert, key, server_crypto);
    let server_addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(run_echo_server(server, 2));

    let session_cache = crypto.get_session_cache();
    let client = client_endpoint(crypto);
    let mut reused = Vec::new();
    for _ in 0..2 {
        let conn = client.connect(server_addr, SERVER_NAME).unwrap();
        let conn = tokio::time::timeout(Duration::from_secs(10), conn)
            .await
            .expect("handshake timed out")
            .unwrap();
        assert_eq!(echo(&conn, b"hello").await, b"hello");
        tokio::time::timeout(Duration::from_secs(10), async {
            while session_cache.get(Bytes::from(SERVER_NAME)).is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("no session ticket received");
        reused.push(handshake_data(&conn).session_reused);
        conn.close(0u32.into(), b"done");
    }
    tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server timed out")
        .unwrap();
    client.wait_idle().await;

    let hellos = CLIENT_HELLOS[SLOT]
        .lock()
        .unwrap()
        .iter()
        .map(|body| ClientHello::parse(body))
        .collect();
    (hellos, reused)
}

/// A QUIC ClientHello shaped like Firefox 156's: context settings on the builder,
/// per-connection settings in the configure-connection callback.
#[tokio::test]
async fn firefox_quic_client_hello() {
    const SIGALGS: [u16; 14] = [
        0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0904, 0x0905, 0x0906, 0x0401,
        0x0501, 0x0601, 0x0201,
    ];
    const DELEGATED_CREDENTIALS: [u16; 7] =
        [0x0403, 0x0503, 0x0603, 0x0203, 0x0904, 0x0905, 0x0906];
    const GROUPS: [u16; 5] = [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019];
    const PERMUTED: [u16; 13] = [
        TLSEXT_SERVER_NAME,
        TLSEXT_STATUS_REQUEST,
        TLSEXT_SUPPORTED_GROUPS,
        TLSEXT_SIGNATURE_ALGORITHMS,
        TLSEXT_ALPN,
        TLSEXT_EXTENDED_MASTER_SECRET,
        TLSEXT_COMPRESS_CERTIFICATE,
        TLSEXT_RECORD_SIZE_LIMIT,
        TLSEXT_DELEGATED_CREDENTIAL,
        TLSEXT_SUPPORTED_VERSIONS,
        TLSEXT_PSK_KEY_EXCHANGE_MODES,
        TLSEXT_KEY_SHARE,
        TLSEXT_RENEGOTIATE,
    ];

    let (cert, key) = self_signed_certificate();
    let mut builder = client_builder(&cert);
    builder.set_preserve_tls13_cipher_list(true);
    // BoringSSL rejects a list without a TLS 1.2 cipher; QUIC only sends the TLS 1.3 ones.
    builder
        .set_cipher_list(
            "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:\
             TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        )
        .unwrap();
    builder
        .set_curves_list("X25519MLKEM768:X25519:P-256:P-384:P-521")
        .unwrap();
    // Includes ML-DSA (0x0904-0x0906), which this build cannot verify itself.
    builder
        .set_advertised_verify_algorithm_prefs(&sigalgs(&SIGALGS))
        .unwrap();
    builder
        .set_delegated_credential_algorithm_prefs(&sigalgs(&DELEGATED_CREDENTIALS))
        .unwrap();
    builder.enable_ocsp_stapling();
    builder.set_record_size_limit(16385);
    builder
        .add_certificate_compression_algorithm(Announced::<1>)
        .unwrap();
    builder
        .add_certificate_compression_algorithm(Announced::<3>)
        .unwrap();
    builder
        .add_certificate_compression_algorithm(Announced::<2>)
        .unwrap();
    builder.set_tls13_legacy_extensions(true);
    builder.set_permute_extensions(true);
    builder
        .set_extension_order_tail(&[
            ExtensionType::QUIC_TRANSPORT_PARAMETERS_STANDARD,
            ExtensionType::ENCRYPTED_CLIENT_HELLO,
        ])
        .unwrap();

    let mut crypto = ClientConfig::from_builder(builder).unwrap();
    let server_names = Arc::new(Mutex::new(Vec::new()));
    let seen = server_names.clone();
    crypto.set_configure_connection_callback(move |ssl, server_name, _params| {
        seen.lock().unwrap().push(server_name.to_owned());
        ssl.set_client_key_shares(&[KeyShare::X25519_MLKEM768, KeyShare::X25519, KeyShare::P256])?;
        ssl.set_enable_ech_grease(true);
        ssl.set_ech_grease_aead(HpkeAead::CHACHA20_POLY1305)?;
        // NSS sizes the GREASE payload like a ClientHelloInner, which grows with a PSK.
        ssl.set_ech_grease_payload_len(if ssl.session().is_some() { 528 } else { 240 });
        Ok(())
    });

    let (hellos, reused) = record_client_hellos::<0>(cert, key, crypto).await;
    assert_eq!(reused, [false, true]);
    assert_eq!(*server_names.lock().unwrap(), [SERVER_NAME, SERVER_NAME]);
    let [full, resumed] = &hellos[..] else {
        panic!("expected two ClientHellos, got {}", hellos.len());
    };

    let tail = [
        TLSEXT_QUIC_TRANSPORT_PARAMETERS,
        TLSEXT_ENCRYPTED_CLIENT_HELLO,
    ];
    let mut expected: HashSet<u16> = PERMUTED.into_iter().chain(tail).collect();
    assert_eq!(full.extension_set(), expected);
    assert!(
        full.extension_types().ends_with(&tail),
        "{:04x?}",
        full.extension_types()
    );
    expected.extend([TLSEXT_EARLY_DATA, TLSEXT_PRE_SHARED_KEY]);
    assert_eq!(resumed.extension_set(), expected);
    assert!(
        resumed
            .extension_types()
            .ends_with(&[tail[0], tail[1], TLSEXT_PRE_SHARED_KEY]),
        "{:04x?}",
        resumed.extension_types()
    );

    for hello in [full, resumed] {
        assert!(!hello.has_grease());
        assert_eq!(hello.cipher_suites, [0x1301, 0x1303, 0x1302]);
        assert_eq!(hello.u16_list(TLSEXT_SIGNATURE_ALGORITHMS), SIGALGS);
        assert_eq!(
            hello.u16_list(TLSEXT_DELEGATED_CREDENTIAL),
            DELEGATED_CREDENTIALS
        );
        assert_eq!(hello.u16_list(TLSEXT_SUPPORTED_GROUPS), GROUPS);
        assert_eq!(hello.key_share_groups(), GROUPS[..3]);
        // zlib, zstd, brotli: the order the algorithms were added in.
        assert_eq!(
            hello.extension(TLSEXT_COMPRESS_CERTIFICATE),
            [6, 0, 1, 0, 3, 0, 2]
        );
        assert_eq!(
            hello.extension(TLSEXT_RECORD_SIZE_LIMIT),
            16385u16.to_be_bytes()
        );
        assert_eq!(hello.extension(TLSEXT_EXTENDED_MASTER_SECRET), b"");
        assert_eq!(hello.extension(TLSEXT_RENEGOTIATE), b"\x00");
    }
    assert_eq!(full.ech_aead_and_payload_len(), (3, 240));
    assert_eq!(resumed.ech_aead_and_payload_len(), (3, 528));
}

/// A QUIC ClientHello shaped like Chrome 153's, without the trust_anchors extension.
#[tokio::test]
async fn chrome_quic_client_hello() {
    const SIGALGS: [u16; 9] = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
    ];
    const EXTENSIONS: [u16; 11] = [
        TLSEXT_ENCRYPTED_CLIENT_HELLO,
        TLSEXT_QUIC_TRANSPORT_PARAMETERS,
        TLSEXT_KEY_SHARE,
        TLSEXT_SUPPORTED_GROUPS,
        TLSEXT_ALPN,
        TLSEXT_SIGNATURE_ALGORITHMS,
        TLSEXT_SUPPORTED_VERSIONS,
        TLSEXT_SERVER_NAME,
        TLSEXT_COMPRESS_CERTIFICATE,
        TLSEXT_PSK_KEY_EXCHANGE_MODES,
        TLSEXT_APPLICATION_SETTINGS,
    ];

    let (cert, key) = self_signed_certificate();
    let mut builder = client_builder(&cert);
    builder
        .set_curves_list("X25519MLKEM768:X25519:P-256:P-384")
        .unwrap();
    builder
        .set_verify_algorithm_prefs(&sigalgs(&SIGALGS))
        .unwrap();
    builder
        .add_certificate_compression_algorithm(Announced::<2>)
        .unwrap();
    builder.set_permute_extensions(true);

    let mut crypto = ClientConfig::from_builder(builder).unwrap();
    crypto.set_configure_connection_callback(|ssl, _, _| {
        // ALPS for h3 with empty client settings.
        ssl.set_alps_use_new_codepoint(true);
        ssl.add_application_settings(b"h3")?;
        ssl.set_enable_ech_grease(true);
        ssl.set_ech_grease_aead(HpkeAead::AES_128_GCM)?;
        ssl.set_client_key_shares(&[KeyShare::X25519_MLKEM768, KeyShare::X25519])?;
        Ok(())
    });

    let (hellos, reused) = record_client_hellos::<1>(cert, key, crypto).await;
    assert_eq!(reused, [false, true]);
    let [full, resumed] = &hellos[..] else {
        panic!("expected two ClientHellos, got {}", hellos.len());
    };

    let mut expected: HashSet<u16> = EXTENSIONS.into_iter().collect();
    assert_eq!(full.extension_set(), expected);
    expected.extend([TLSEXT_EARLY_DATA, TLSEXT_PRE_SHARED_KEY]);
    assert_eq!(resumed.extension_set(), expected);
    assert_eq!(
        resumed.extension_types().last(),
        Some(&TLSEXT_PRE_SHARED_KEY)
    );

    for hello in [full, resumed] {
        assert!(!hello.has_grease());
        assert_eq!(hello.u16_list(TLSEXT_SIGNATURE_ALGORITHMS), SIGALGS);
        assert_eq!(hello.key_share_groups(), [0x11ec, 0x001d]);
        assert_eq!(hello.extension(TLSEXT_COMPRESS_CERTIFICATE), [2, 0, 2]);
        assert_eq!(
            hello.extension(TLSEXT_APPLICATION_SETTINGS),
            b"\x00\x03\x02h3"
        );
        let (aead, payload_len) = hello.ech_aead_and_payload_len();
        assert_eq!(aead, 1);
        assert!([144, 176, 208, 240].contains(&payload_len), "{payload_len}");
    }
}

/// What the second connection in [resume_session] did.
struct Resumption {
    /// `None` if `into_0rtt` refused, otherwise whether the server accepted the early data.
    zero_rtt_accepted: Option<bool>,
    client_reused: bool,
    server_reused: bool,
    /// The ClientHello of the second connection.
    client_hello: ClientHello,
}

/// Connects twice to a server that issues session tickets with or without early data and
/// records the ClientHellos in `CLIENT_HELLOS[SLOT]`. Both connections try `into_0rtt`; the
/// second offers the ticket of the first and, if 0-RTT is possible, sends its request as early
/// data.
async fn resume_session<const SLOT: usize>(early_data: bool) -> Resumption {
    let (cert, key) = self_signed_certificate();
    let mut server_crypto = ServerConfig::new().unwrap();
    server_crypto.ctx_mut().enable_early_data(early_data);
    server_crypto
        .ctx_mut()
        .set_select_certificate_cb(Some(record_client_hello::<SLOT>));
    let server = server_endpoint(cert.clone(), key, server_crypto);
    let server_addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(run_echo_server(server, 2));

    let mut crypto = ClientConfig::from_builder(client_builder(&cert)).unwrap();
    let ctx = crypto.ctx().clone();
    let session_cache = CountingCache::new();
    crypto.set_session_cache(session_cache.clone());
    let client = client_endpoint(crypto);
    let cache_key = Bytes::from(SERVER_NAME);

    let connecting = client.connect(server_addr, SERVER_NAME).unwrap();
    let Err(connecting) = connecting.into_0rtt() else {
        panic!("0-RTT without a session");
    };
    let conn = tokio::time::timeout(Duration::from_secs(10), connecting)
        .await
        .expect("handshake timed out")
        .unwrap();
    assert_eq!(echo(&conn, b"first").await, b"first");
    assert!(!handshake_data(&conn).session_reused);
    // A BoringSSL server sends two tickets.
    session_cache.wait_for(2).await;
    let newest = session_cache.get(cache_key.clone()).unwrap();
    let ticket = Entry::decode(&ctx, newest.clone()).unwrap();
    assert_eq!(ticket.session.early_data_capable(), early_data);
    conn.close(0u32.into(), b"done");

    // A TLS 1.3 ticket is single-use: the connection takes the newest ticket out of the cache
    // and leaves the older one.
    let connecting = client.connect(server_addr, SERVER_NAME).unwrap();
    let older = session_cache
        .take(cache_key.clone())
        .expect("no ticket left");
    assert_ne!(older, newest, "the connection left its ticket in the cache");
    assert!(session_cache.get(cache_key).is_none(), "a third ticket");
    let (conn, zero_rtt_accepted) = match connecting.into_0rtt() {
        Ok((conn, accepted)) => {
            // The request goes out as 0-RTT data, before the handshake completes.
            let response = tokio::time::timeout(Duration::from_secs(10), echo(&conn, b"second"))
                .await
                .expect("echo timed out");
            assert_eq!(response, b"second");
            let accepted = accepted.await;
            (conn, Some(accepted))
        }
        Err(connecting) => {
            let conn = tokio::time::timeout(Duration::from_secs(10), connecting)
                .await
                .expect("handshake timed out")
                .unwrap();
            assert_eq!(echo(&conn, b"second").await, b"second");
            (conn, None)
        }
    };
    let client_reused = handshake_data(&conn).session_reused;
    conn.close(0u32.into(), b"done");

    let server_seen = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server timed out")
        .unwrap();
    client.wait_idle().await;

    let hellos = CLIENT_HELLOS[SLOT].lock().unwrap();
    assert_eq!(hellos.len(), 2, "ClientHellos");
    Resumption {
        zero_rtt_accepted,
        client_reused,
        server_reused: server_seen[1].session_reused,
        client_hello: ClientHello::parse(&hellos[1]),
    }
}

/// A ticket that allows early data resumes the session with 0-RTT.
#[tokio::test]
async fn resumption_with_early_data() {
    let resumption = resume_session::<2>(true).await;
    assert_eq!(resumption.zero_rtt_accepted, Some(true), "0-RTT");
    assert!(resumption.client_reused, "client session_reused");
    assert!(resumption.server_reused, "server session_reused");
    let extensions = resumption.client_hello.extension_set();
    assert!(extensions.contains(&TLSEXT_PRE_SHARED_KEY));
    assert!(extensions.contains(&TLSEXT_EARLY_DATA));
}

/// A ticket without early data (as www.cloudflare.com sends them over QUIC) still resumes the
/// session with a PSK, but `into_0rtt` refuses and the handshake takes a round trip.
#[tokio::test]
async fn resumption_without_early_data() {
    let resumption = resume_session::<3>(false).await;
    assert_eq!(resumption.zero_rtt_accepted, None, "into_0rtt succeeded");
    assert!(resumption.client_reused, "client session_reused");
    assert!(resumption.server_reused, "server session_reused");
    let extensions = resumption.client_hello.extension_set();
    assert!(extensions.contains(&TLSEXT_PRE_SHARED_KEY));
    assert!(!extensions.contains(&TLSEXT_EARLY_DATA));
}

/// Two connections started after one handshake, before new tickets arrive, both resume: the
/// cache keeps both tickets the server sent, and each connection takes one.
#[tokio::test]
async fn parallel_connections_resume() {
    let (cert, key) = self_signed_certificate();
    let server = server_endpoint(cert.clone(), key, ServerConfig::new().unwrap());
    let server_addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(run_echo_server(server, 3));

    let mut crypto = ClientConfig::from_builder(client_builder(&cert)).unwrap();
    let session_cache = CountingCache::new();
    crypto.set_session_cache(session_cache.clone());
    let client = client_endpoint(crypto);

    let conn = client.connect(server_addr, SERVER_NAME).unwrap();
    let conn = tokio::time::timeout(Duration::from_secs(10), conn)
        .await
        .expect("handshake timed out")
        .unwrap();
    assert_eq!(echo(&conn, b"first").await, b"first");
    // A BoringSSL server sends two tickets.
    session_cache.wait_for(2).await;
    let first_reused = handshake_data(&conn).session_reused;
    conn.close(0u32.into(), b"done");

    let second = client.connect(server_addr, SERVER_NAME).unwrap();
    let third = client.connect(server_addr, SERVER_NAME).unwrap();
    assert!(
        session_cache.get(Bytes::from(SERVER_NAME)).is_none(),
        "a ticket is left after two connections"
    );
    let resume = |connecting: quinn::Connecting, request: &'static [u8]| async move {
        let conn = tokio::time::timeout(Duration::from_secs(10), connecting)
            .await
            .expect("handshake timed out")
            .unwrap();
        assert_eq!(echo(&conn, request).await, request);
        let reused = handshake_data(&conn).session_reused;
        conn.close(0u32.into(), b"done");
        reused
    };
    let (second_reused, third_reused) =
        tokio::join!(resume(second, b"second"), resume(third, b"third"));

    let server_seen = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server timed out")
        .unwrap();
    client.wait_idle().await;

    assert_eq!(
        [first_reused, second_reused, third_reused],
        [false, true, true],
        "client session_reused"
    );
    let server_reused: Vec<bool> = server_seen.iter().map(|d| d.session_reused).collect();
    assert_eq!(server_reused, [false, true, true], "server session_reused");
}

/// The type of a QUIC packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    OneRtt,
}

/// The packets coalesced in `datagram`: their types and, for long header packets, their QUIC
/// version. Long headers are not protected beyond the packet number, so this works without keys.
fn packets(mut datagram: &[u8]) -> (Vec<PacketType>, Vec<u32>) {
    let mut types = Vec::new();
    let mut versions = Vec::new();
    while let Some(&first) = datagram.first() {
        if first & 0x80 == 0 {
            // A short header packet fills the rest of the datagram.
            types.push(PacketType::OneRtt);
            break;
        }
        let version = u32::from_be_bytes(datagram[1..5].try_into().unwrap());
        // Version 2 numbers the types differently (RFC 9369, section 3.2).
        let bits = (first >> 4) & 0x03;
        let bits = if version == QUIC_VERSION_2 {
            bits.wrapping_sub(1) & 0x03
        } else {
            bits
        };
        let packet_type = match bits {
            0 => PacketType::Initial,
            1 => PacketType::ZeroRtt,
            2 => PacketType::Handshake,
            _ => PacketType::Retry,
        };
        types.push(packet_type);
        versions.push(version);
        if packet_type == PacketType::Retry {
            break;
        }
        let mut packet = Reader(&datagram[5..]); // first byte, version
        let len = packet.u8();
        packet.take(len); // destination connection ID
        let len = packet.u8();
        packet.take(len); // source connection ID
        if packet_type == PacketType::Initial {
            let len = varint(&mut packet);
            packet.take(len); // token
        }
        let len = varint(&mut packet);
        packet.take(len); // packet number and payload
        datagram = packet.0;
    }
    (types, versions)
}

fn varint(reader: &mut Reader) -> usize {
    let first = reader.u8();
    let len = 1 << (first >> 6);
    reader
        .take(len - 1)
        .iter()
        .fold(first & 0x3f, |value, &byte| (value << 8) | byte as usize)
}

// ============================================================
// Initial packet protection (RFC 9001 §5), to read a client's raw ClientHello off the wire
// independent of what btls itself reports through a callback (which, once ECH is accepted,
// reflects the decrypted ClientHelloInner instead - see `ech_outer_transport_params_are_on_the_wire...`
// below). Initial keys derive from the destination connection ID alone (RFC 9001 §5.2), which
// makes this a plain, public computation, not something that needs any of btls's own secrets.
// ============================================================

/// initial_salt of QUIC version 1 (RFC 9001 §5.2).
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::init(key, &MessageDigest::sha256()).unwrap();
    hmac.update(data).unwrap();
    hmac.finalize().unwrap()
}

/// HKDF-Expand-Label with an empty context (RFC 8446 §7.1), for outputs of at most one SHA-256
/// block.
fn hkdf_expand_label(secret: &[u8], label: &str, len: usize) -> Vec<u8> {
    let label = format!("tls13 {label}");
    let mut info = (len as u16).to_be_bytes().to_vec();
    info.push(label.len() as u8);
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    info.push(1); // HKDF-Expand block counter
    let mut out = hmac_sha256(secret, &info);
    out.truncate(len);
    out
}

/// The client's Initial packet protection keys.
struct InitialKeys {
    key: Vec<u8>,
    iv: Vec<u8>,
    hp: Vec<u8>,
}

fn client_initial_keys(dcid: &[u8]) -> InitialKeys {
    let initial_secret = hmac_sha256(&INITIAL_SALT_V1, dcid);
    let secret = hkdf_expand_label(&initial_secret, "client in", 32);
    InitialKeys {
        key: hkdf_expand_label(&secret, "quic key", 16),
        iv: hkdf_expand_label(&secret, "quic iv", 12),
        hp: hkdf_expand_label(&secret, "quic hp", 16),
    }
}

fn qvarint(buf: &[u8], p: &mut usize) -> u64 {
    let len = 1 << (buf[*p] >> 6);
    let mut value = u64::from(buf[*p] & 0x3f);
    for i in 1..len {
        value = (value << 8) | u64::from(buf[*p + i]);
    }
    *p += len;
    value
}

/// A decrypted client Initial packet's CRYPTO frames (offset and data); `None` for anything but
/// an Initial, or a version 1 one.
fn open_initial(buf: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let first = buf[0];
    if first & 0x80 == 0 || (first >> 4) & 0x03 != 0 || buf[1..5] != [0, 0, 0, 1] {
        return None;
    }
    let mut p = 5;
    let dcid = buf[p + 1..p + 1 + buf[p] as usize].to_vec();
    p += 1 + dcid.len();
    p += 1 + buf[p] as usize; // source connection ID
    let token_len = qvarint(buf, &mut p) as usize;
    p += token_len;
    let length = qvarint(buf, &mut p) as usize;
    let pn_offset = p;

    let keys = client_initial_keys(&dcid);
    let sample = &buf[pn_offset + 4..pn_offset + 20];
    let mask = encrypt(Cipher::aes_128_ecb(), &keys.hp, None, sample).unwrap();
    let mut header = buf[..pn_offset + 4].to_vec();
    header[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(header[0] & 0x03) + 1;
    header.truncate(pn_offset + pn_len);
    let mut pn = 0u64;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | u64::from(header[pn_offset + i]);
    }
    let end = pn_offset + length;
    let mut nonce = keys.iv.clone();
    for (i, byte) in pn.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= byte;
    }
    let payload = decrypt_aead(
        Cipher::aes_128_gcm(),
        &keys.key,
        Some(&nonce),
        &header,
        &buf[pn_offset + pn_len..end - 16],
        &buf[end - 16..end],
    )
    .ok()?;

    // Only CRYPTO frames are of interest here; anything else (PADDING, PING, ACK, ...) that
    // isn't understood just ends the scan of this packet's payload instead of failing it -
    // a later Initial-space packet (an ACK of the server's response, say) carries only frames
    // this parser has no reason to support.
    let mut crypto = Vec::new();
    let mut q = 0;
    while q < payload.len() {
        match payload[q] {
            0x00 => {
                while q < payload.len() && payload[q] == 0 {
                    q += 1;
                }
            }
            0x01 => q += 1,
            0x06 => {
                q += 1;
                let offset = qvarint(&payload, &mut q);
                let len = qvarint(&payload, &mut q) as usize;
                crypto.push((offset, payload[q..q + len].to_vec()));
                q += len;
            }
            _ => break,
        }
    }
    Some(crypto)
}

/// Reassembles CRYPTO frames (offset, data) from one or more Initial packets into the first
/// complete handshake message, if there is one.
fn reassemble_crypto(frames: &[(u64, Vec<u8>)]) -> Option<Vec<u8>> {
    let mut stream = Vec::new();
    let mut frames: Vec<&(u64, Vec<u8>)> = frames.iter().collect();
    frames.sort_by_key(|(offset, _)| *offset);
    for (offset, data) in frames {
        let offset = *offset as usize;
        if offset > stream.len() {
            return None;
        }
        let end = offset + data.len();
        if end > stream.len() {
            stream.extend_from_slice(&data[stream.len() - offset..]);
        }
    }
    if stream.len() < 4 {
        return None;
    }
    let len = 4 + ((stream[1] as usize) << 16 | (stream[2] as usize) << 8 | stream[3] as usize);
    (stream.len() >= len).then(|| stream[..len].to_vec())
}

/// A datagram the relay received.
struct Datagram {
    sent: Instant,
    packet_types: Vec<PacketType>,
    /// The versions of its long header packets.
    versions: Vec<u32>,
    /// The datagram's own bytes, exactly as received.
    bytes: Vec<u8>,
}

impl Datagram {
    fn new(bytes: &[u8]) -> Self {
        let (packet_types, versions) = packets(bytes);
        Datagram {
            sent: Instant::now(),
            packet_types,
            versions,
            bytes: bytes.to_vec(),
        }
    }
}

/// Forwards datagrams between a client and a server, each after a delay, and records them.
struct Relay {
    addr: SocketAddr,
    client_datagrams: Arc<Mutex<Vec<Datagram>>>,
    server_datagrams: Arc<Mutex<Vec<Datagram>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Relay {
    async fn start(server: SocketAddr, delay: Duration) -> Relay {
        let client_side = Arc::new(
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap(),
        );
        let server_side = Arc::new(
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap(),
        );
        server_side.connect(server).await.unwrap();
        let addr = client_side.local_addr().unwrap();
        let client_datagrams = Arc::new(Mutex::new(Vec::new()));
        let server_datagrams = Arc::new(Mutex::new(Vec::new()));
        let client_addr = Arc::new(Mutex::new(None));
        let (to_server, mut for_server) = tokio::sync::mpsc::unbounded_channel();
        let (to_client, mut for_client) = tokio::sync::mpsc::unbounded_channel();
        let due = move || tokio::time::Instant::now() + delay;

        let mut tasks = Vec::new();
        // Receive errors report ICMP messages on Windows; keep going.
        let (socket, record, peer) = (
            client_side.clone(),
            client_datagrams.clone(),
            client_addr.clone(),
        );
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0; 65536];
            loop {
                let Ok((len, from)) = socket.recv_from(&mut buf).await else {
                    continue;
                };
                record.lock().unwrap().push(Datagram::new(&buf[..len]));
                *peer.lock().unwrap() = Some(from);
                let _ = to_server.send((due(), buf[..len].to_vec()));
            }
        }));
        let (socket, record) = (server_side.clone(), server_datagrams.clone());
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0; 65536];
            loop {
                let Ok(len) = socket.recv(&mut buf).await else {
                    continue;
                };
                record.lock().unwrap().push(Datagram::new(&buf[..len]));
                let _ = to_client.send((due(), buf[..len].to_vec()));
            }
        }));
        tasks.push(tokio::spawn(async move {
            while let Some((due, datagram)) = for_server.recv().await {
                tokio::time::sleep_until(due).await;
                let _ = server_side.send(&datagram).await;
            }
        }));
        tasks.push(tokio::spawn(async move {
            while let Some((due, datagram)) = for_client.recv().await {
                tokio::time::sleep_until(due).await;
                let peer = client_addr.lock().unwrap().unwrap();
                let _ = client_side.send_to(&datagram, peer).await;
            }
        }));

        Relay {
            addr,
            client_datagrams,
            server_datagrams,
            tasks,
        }
    }

    /// The versions of the long header packets in each datagram the client and the server sent
    /// since the last call.
    fn take_versions(&self) -> (Vec<Vec<u32>>, Vec<Vec<u32>>) {
        let take = |datagrams: &Mutex<Vec<Datagram>>| {
            let datagrams = std::mem::take(&mut *datagrams.lock().unwrap());
            datagrams
                .into_iter()
                .map(|datagram| datagram.versions)
                .filter(|versions| !versions.is_empty())
                .collect()
        };
        (take(&self.client_datagrams), take(&self.server_datagrams))
    }

    /// The raw bytes of every datagram the client has sent so far, in order.
    fn client_datagrams(&self) -> Vec<Vec<u8>> {
        self.client_datagrams
            .lock()
            .unwrap()
            .iter()
            .map(|datagram| datagram.bytes.clone())
            .collect()
    }

    /// The first datagram the client sent after `after` (if given) that fulfills `select`: when
    /// it was sent, and the types of its packets.
    fn first_sent(
        &self,
        after: Option<Instant>,
        select: impl Fn(&[PacketType]) -> bool,
    ) -> Option<(Instant, Vec<PacketType>)> {
        self.client_datagrams
            .lock()
            .unwrap()
            .iter()
            .filter(|datagram| after.is_none_or(|after| datagram.sent > after))
            .find(|datagram| select(&datagram.packet_types))
            .map(|datagram| (datagram.sent, datagram.packet_types.clone()))
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Runs verification jobs on tokio's blocking threads, each taking at least `delay`, and
/// records when their delay was over, just before they verify.
fn delayed_spawner(
    delay: Duration,
    verified: Arc<Mutex<Vec<Instant>>>,
) -> impl Fn(VerifyJob) + Send + Sync + 'static {
    move |job| {
        let verified = verified.clone();
        tokio::task::spawn_blocking(move || {
            std::thread::sleep(delay);
            verified.lock().unwrap().push(Instant::now());
            job();
        });
    }
}

/// With the certificate verified on another thread, the client acknowledges the server's
/// Handshake packets while the verification runs and sends its Finished as soon as it is done,
/// as Chrome does. The relay delays every datagram by 25 ms, so that a probe timeout could not
/// pass unnoticed.
#[tokio::test]
async fn async_verification_acks_before_finished() {
    let (cert, key) = self_signed_certificate();
    let server = server_endpoint(cert.clone(), key, ServerConfig::new().unwrap());
    let relay = Relay::start(server.local_addr().unwrap(), Duration::from_millis(25)).await;
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let established = Instant::now();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let request = recv.read_to_end(1024).await.unwrap();
        send.write_all(&request).await.unwrap();
        send.finish().unwrap();
        conn.closed().await;
        established
    });

    let verified = Arc::new(Mutex::new(Vec::new()));
    let mut builder = client_builder(&cert);
    builder.set_async_default_verify(delayed_spawner(Duration::from_millis(5), verified.clone()));
    let client = client_endpoint(ClientConfig::from_builder(builder).unwrap());
    let conn = client.connect(relay.addr, SERVER_NAME).unwrap();
    let conn = tokio::time::timeout(Duration::from_secs(10), conn)
        .await
        .expect("handshake timed out")
        .unwrap();
    assert_eq!(echo(&conn, b"async").await, b"async");
    conn.close(0u32.into(), b"done");
    let established = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server timed out")
        .unwrap();
    client.wait_idle().await;

    let [verified] = verified.lock().unwrap()[..] else {
        panic!("expected one verification");
    };
    let has_handshake = |types: &[PacketType]| types.contains(&PacketType::Handshake);
    // The client sent a Handshake packet while the verification ran, when it had no Finished
    // yet: an acknowledgement.
    let (ack, _) = relay.first_sent(None, has_handshake).unwrap();
    assert!(ack < verified);
    // The next datagram carries the Finished and left right after the verification, not after a
    // probe timeout and a probe's acknowledgement from the server, which take more than 100 ms
    // here.
    let (finished, types) = relay.first_sent(Some(verified), |_| true).unwrap();
    assert!(has_handshake(&types), "{types:?}");
    assert!(
        finished - verified < Duration::from_millis(20),
        "Finished {:?} after the verification",
        finished - verified
    );
    // Only then the server completed the handshake, and the client sent 1-RTT packets.
    assert!(established > verified);
    let one_rtt = |types: &[PacketType]| types.contains(&PacketType::OneRtt);
    assert!(relay.first_sent(None, one_rtt).unwrap().0 >= finished);
    eprintln!(
        "Handshake ACK {:?} before the verification finished, Finished {:?} after it",
        verified - ack,
        finished - verified
    );
}

/// Connects to a server with `cert` and `key` as `server_name`, with certificate verification
/// set up on `builder`, and returns the error the handshake fails with.
async fn handshake_error(
    cert: X509,
    key: PKey<Private>,
    builder: SslContextBuilder,
    server_name: &str,
) -> quinn::ConnectionError {
    let server = server_endpoint(cert, key, ServerConfig::new().unwrap());
    let server_addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        assert!(
            incoming.await.is_err(),
            "the server completed the handshake"
        );
    });

    let client = client_endpoint(ClientConfig::from_builder(builder).unwrap());
    let conn = client.connect(server_addr, server_name).unwrap();
    let error = tokio::time::timeout(Duration::from_secs(10), conn)
        .await
        .expect("handshake timed out")
        .unwrap_err();
    tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server timed out")
        .unwrap();
    client.wait_idle().await;
    error
}

/// A certificate that fails verification on another thread fails the handshake with the same
/// error as with the built-in verification.
#[tokio::test]
async fn async_verification_failures_match_sync() {
    const UNKNOWN_CA: u8 = 48;
    const BAD_CERTIFICATE: u8 = 42;

    let (cert, key) = self_signed_certificate();
    let untrusted = || {
        let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
        // No cert store configured (no CA trusted); verification must still be turned on
        // explicitly, same as `client_builder` does for the trusted case below.
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        builder
    };
    let trusted = || client_builder(&cert);
    let cases: [(&dyn Fn() -> SslContextBuilder, &str, u8); 2] = [
        (&untrusted, SERVER_NAME, UNKNOWN_CA),
        (&trusted, "example.com", BAD_CERTIFICATE),
    ];

    for (builder, server_name, alert) in cases {
        let sync = handshake_error(cert.clone(), key.clone(), builder(), server_name).await;
        let quinn::ConnectionError::TransportError(error) = &sync else {
            panic!("unexpected error: {sync:?}");
        };
        assert_eq!(error.code, quinn::TransportErrorCode::crypto(alert));

        let verified = Arc::new(Mutex::new(Vec::new()));
        let mut offloaded = builder();
        offloaded
            .set_async_default_verify(delayed_spawner(Duration::from_millis(5), verified.clone()));
        let error = handshake_error(cert.clone(), key.clone(), offloaded, server_name).await;
        assert_eq!(error, sync);
        assert_eq!(verified.lock().unwrap().len(), 1, "verifications");
    }
}

/// An endpoint that supports the QUIC `versions`, preferring them in this order.
fn endpoint_with_versions(
    server: Option<quinn::ServerConfig>,
    versions: &[u32],
) -> quinn::Endpoint {
    let mut config = helpers::default_endpoint_config();
    config.supported_versions(versions.to_vec());
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    quinn::Endpoint::new(config, server, socket, Arc::new(quinn::TokioRuntime)).unwrap()
}

/// A server that supports QUIC versions 2 and 1 and prefers 2, so that it switches a client
/// that offers version 2 to it (compatible version negotiation, RFC 9368). Its session tickets
/// allow early data.
fn v2_server(cert: X509, key: PKey<Private>) -> quinn::Endpoint {
    let mut crypto = ServerConfig::new().unwrap();
    crypto.ctx_mut().set_certificate(cert).unwrap();
    crypto.ctx_mut().set_private_key(key).unwrap();
    crypto.ctx_mut().enable_early_data(true);
    let config = helpers::server_config(Arc::new(crypto)).unwrap();
    endpoint_with_versions(Some(config), &[QUIC_VERSION_2, 1])
}

/// A client context that trusts `cert` and sends a ClientHello that fits into one Initial packet:
/// Quinn switches a connection to another version only then, and a key share for X25519MLKEM768
/// alone is 1216 bytes.
fn small_client_hello_builder(cert: &X509) -> SslContextBuilder {
    let mut builder = client_builder(cert);
    builder.set_curves_list("X25519").unwrap();
    builder
}

/// A client configuration that starts in QUIC `version` and, if `offer_v2`, lists versions 2 and
/// 1 in version_information, as Firefox does.
fn versioned_client(
    crypto: Arc<ClientConfig>,
    version: u32,
    offer_v2: bool,
) -> quinn::ClientConfig {
    let mut config = quinn::ClientConfig::new(crypto);
    config.version(version);
    if offer_v2 {
        let mut layout = quinn::TransportParameterLayout::default();
        layout
            .version_information(Some(quinn::VersionInformation::new(vec![
                QUIC_VERSION_2,
                1,
            ])))
            .unwrap();
        let mut transport = quinn::TransportConfig::default();
        transport.transport_parameter_layout(layout);
        config.transport_config(Arc::new(transport));
    }
    config
}

/// What a connection through the relay did.
#[derive(Debug)]
struct VersionedConnection {
    /// `None` if the client did not attempt 0-RTT, otherwise whether the server accepted it.
    zero_rtt: Option<bool>,
    session_reused: bool,
    /// The versions of the long header packets in each datagram of the client and the server.
    client: Vec<Vec<u32>>,
    server: Vec<Vec<u32>>,
}

impl VersionedConnection {
    /// Whether every long header packet of both sides used `version`.
    fn only(&self, version: u32) -> bool {
        self.client
            .iter()
            .chain(&self.server)
            .flatten()
            .all(|&v| v == version)
    }
}

/// Connects through `relay` with `config`, sending the request as 0-RTT data if the client can,
/// and waits until the client stored `tickets` sessions in all.
async fn connect_versioned(
    endpoint: &quinn::Endpoint,
    relay: &Relay,
    config: quinn::ClientConfig,
    cache: &CountingCache,
    tickets: usize,
) -> VersionedConnection {
    let connecting = endpoint
        .connect_with(config, relay.addr, SERVER_NAME)
        .unwrap();
    let (conn, zero_rtt) = match connecting.into_0rtt() {
        Ok((conn, accepted)) => {
            let early = async {
                let (mut send, mut recv) = conn.open_bi().await.ok()?;
                send.write_all(b"early").await.ok()?;
                send.finish().ok()?;
                recv.read_to_end(1024).await.ok()
            };
            let response = tokio::time::timeout(Duration::from_secs(10), early)
                .await
                .expect("echo timed out");
            let accepted = accepted.await;
            if accepted {
                assert_eq!(response.as_deref(), Some(&b"early"[..]));
            } else {
                // Streams of rejected 0-RTT data fail; the request goes again.
                assert_eq!(response, None);
                assert_eq!(echo(&conn, b"late").await, b"late");
            }
            (conn, Some(accepted))
        }
        Err(connecting) => {
            let conn = tokio::time::timeout(Duration::from_secs(10), connecting)
                .await
                .expect("handshake timed out")
                .unwrap();
            assert_eq!(echo(&conn, b"late").await, b"late");
            (conn, None)
        }
    };
    cache.wait_for(tickets).await;
    let session_reused = handshake_data(&conn).session_reused;
    conn.close(0u32.into(), b"done");
    let (client, server) = relay.take_versions();
    VersionedConnection {
        zero_rtt,
        session_reused,
        client,
        server,
    }
}

/// A connection in QUIC version 2 uses it throughout, and a second one resumes the session with
/// 0-RTT. The tickets are kept apart from those of version 1.
#[tokio::test]
async fn version_2_handshake_and_resumption() {
    let (cert, key) = self_signed_certificate();
    let server = v2_server(cert.clone(), key);
    let relay = Relay::start(server.local_addr().unwrap(), Duration::ZERO).await;
    let server_task = tokio::spawn(run_echo_server(server, 2));

    let mut crypto = ClientConfig::from_builder(client_builder(&cert)).unwrap();
    let cache = CountingCache::new();
    crypto.set_session_cache(cache.clone());
    let crypto = Arc::new(crypto);
    let client = endpoint_with_versions(None, &[1, QUIC_VERSION_2]);

    let config = || versioned_client(crypto.clone(), QUIC_VERSION_2, false);
    let first = connect_versioned(&client, &relay, config(), &cache, 2).await;
    assert!(first.only(QUIC_VERSION_2), "{first:?}");
    assert!(!first.client.is_empty() && !first.server.is_empty());
    assert_eq!(first.zero_rtt, None);
    assert!(!first.session_reused);
    let v2_key = session_cache_key(SERVER_NAME, QUIC_VERSION_2);
    assert!(cache.get(v2_key).is_some(), "no version 2 ticket");
    assert!(
        cache.get(Bytes::from(SERVER_NAME)).is_none(),
        "a version 1 ticket"
    );

    let second = connect_versioned(&client, &relay, config(), &cache, 4).await;
    assert!(second.only(QUIC_VERSION_2), "{second:?}");
    assert_eq!(second.zero_rtt, Some(true));
    assert!(second.session_reused);

    let server_seen = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server timed out")
        .unwrap();
    let server_reused: Vec<bool> = server_seen.iter().map(|d| d.session_reused).collect();
    assert_eq!(server_reused, [false, true]);
    client.wait_idle().await;
}

/// A client that starts in version 1 and offers version 2 follows a server that prefers it
/// (compatible version negotiation, RFC 9368). The tickets of that connection belong to version 2
/// (RFC 9369, section 5): the next connection in version 1 does not offer them, one in version 2
/// resumes with 0-RTT.
#[tokio::test]
async fn compatible_version_negotiation() {
    let (cert, key) = self_signed_certificate();
    let server = v2_server(cert.clone(), key);
    let relay = Relay::start(server.local_addr().unwrap(), Duration::ZERO).await;
    let server_task = tokio::spawn(run_echo_server(server, 3));

    let mut crypto = ClientConfig::from_builder(small_client_hello_builder(&cert)).unwrap();
    let cache = CountingCache::new();
    crypto.set_session_cache(cache.clone());
    let crypto = Arc::new(crypto);
    let client = endpoint_with_versions(None, &[1, QUIC_VERSION_2]);
    let offering_v2 = |version| versioned_client(crypto.clone(), version, true);

    let switched = connect_versioned(&client, &relay, offering_v2(1), &cache, 2).await;
    // The client's first flight is in version 1, everything after it in version 2.
    let (first_flight, rest) = switched.client.split_first().unwrap();
    assert!(first_flight.iter().all(|&v| v == 1), "{switched:?}");
    assert!(!rest.is_empty());
    assert!(
        rest.iter().flatten().all(|&v| v == QUIC_VERSION_2),
        "{switched:?}"
    );
    assert!(
        switched
            .server
            .iter()
            .flatten()
            .all(|&v| v == QUIC_VERSION_2),
        "{switched:?}"
    );
    assert!(!switched.session_reused);
    let v2_key = session_cache_key(SERVER_NAME, QUIC_VERSION_2);
    assert!(cache.get(v2_key).is_some(), "no version 2 ticket");
    assert!(
        cache.get(Bytes::from(SERVER_NAME)).is_none(),
        "a version 1 ticket"
    );

    // Starting in version 1 again, the client has no ticket to offer, and is switched again.
    let again = connect_versioned(&client, &relay, offering_v2(1), &cache, 4).await;
    assert_eq!(again.zero_rtt, None);
    assert!(!again.session_reused);
    assert!(
        again.server.iter().flatten().all(|&v| v == QUIC_VERSION_2),
        "{again:?}"
    );

    // Starting in version 2, it resumes with 0-RTT.
    let resumed = connect_versioned(&client, &relay, offering_v2(QUIC_VERSION_2), &cache, 6).await;
    assert!(resumed.only(QUIC_VERSION_2), "{resumed:?}");
    assert_eq!(resumed.zero_rtt, Some(true));
    assert!(resumed.session_reused);

    let server_seen = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server timed out")
        .unwrap();
    let server_reused: Vec<bool> = server_seen.iter().map(|d| d.session_reused).collect();
    assert_eq!(server_reused, [false, false, true]);
    client.wait_idle().await;
}

/// A [SessionCache] that hands out the version 1 sessions whatever the key, as a client that does
/// not keep sessions apart by version would.
struct VersionBlindCache(Arc<CountingCache>);

impl SessionCache for VersionBlindCache {
    fn put(&self, key: Bytes, value: Bytes) {
        self.0.put(key, value)
    }

    fn get(&self, _: Bytes) -> Option<Bytes> {
        self.0.get(Bytes::from(SERVER_NAME))
    }

    fn take(&self, _: Bytes) -> Option<Bytes> {
        self.0.take(Bytes::from(SERVER_NAME))
    }

    fn remove(&self, _: Bytes) {
        self.0.remove(Bytes::from(SERVER_NAME))
    }

    fn clear(&self) {
        self.0.clear()
    }
}

/// 0-RTT and versions: a client that attempts 0-RTT with a ticket of version 1 is not switched to
/// version 2, as 0-RTT only goes in the original version (RFC 9369, section 4.1), and a server
/// refuses a ticket of version 1, and so its 0-RTT data, on a connection in version 2 (RFC 9369,
/// section 5).
#[tokio::test]
async fn zero_rtt_and_versions() {
    let (cert, key) = self_signed_certificate();
    let server = v2_server(cert.clone(), key);
    let relay = Relay::start(server.local_addr().unwrap(), Duration::ZERO).await;
    let server_task = tokio::spawn(run_echo_server(server, 3));

    let cache = CountingCache::new();
    let mut crypto = ClientConfig::from_builder(small_client_hello_builder(&cert)).unwrap();
    crypto.set_session_cache(cache.clone());
    let crypto = Arc::new(crypto);
    let client = endpoint_with_versions(None, &[1, QUIC_VERSION_2]);

    // Version 1 without offering version 2: the server keeps it, and the tickets are version 1's.
    let plain = versioned_client(crypto.clone(), 1, false);
    let plain = connect_versioned(&client, &relay, plain, &cache, 2).await;
    assert!(plain.only(1), "{plain:?}");

    // Offering version 2 and attempting 0-RTT with a version 1 ticket: no switch, 0-RTT accepted.
    let early = versioned_client(crypto.clone(), 1, true);
    let early = connect_versioned(&client, &relay, early, &cache, 4).await;
    assert!(early.only(1), "{early:?}");
    assert_eq!(early.zero_rtt, Some(true));
    assert!(early.session_reused);

    // A version 1 ticket offered on a version 2 connection: the server does not resume the
    // session and rejects the 0-RTT data, which goes again in 1-RTT packets.
    let mut blind = ClientConfig::from_builder(small_client_hello_builder(&cert)).unwrap();
    blind.set_session_cache(Arc::new(VersionBlindCache(cache.clone())));
    let crossed = versioned_client(Arc::new(blind), QUIC_VERSION_2, false);
    let crossed = connect_versioned(&client, &relay, crossed, &cache, 6).await;
    assert!(crossed.only(QUIC_VERSION_2), "{crossed:?}");
    assert_eq!(crossed.zero_rtt, Some(false));
    assert!(!crossed.session_reused);

    let server_seen = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server timed out")
        .unwrap();
    let server_reused: Vec<bool> = server_seen.iter().map(|d| d.session_reused).collect();
    assert_eq!(server_reused, [false, true, false]);
    client.wait_idle().await;
}

/// A version quinn-btls does not know fails the connection attempt instead of panicking.
#[tokio::test]
async fn unknown_version_is_refused() {
    const UNKNOWN: u32 = 0x1a2a_3a4a;
    let (cert, _) = self_signed_certificate();
    let crypto = ClientConfig::from_builder(client_builder(&cert)).unwrap();
    let client = endpoint_with_versions(None, &[1, UNKNOWN]);
    let config = versioned_client(Arc::new(crypto), UNKNOWN, false);
    let result = client.connect_with(config, (Ipv4Addr::LOCALHOST, 443).into(), SERVER_NAME);
    assert!(matches!(
        result,
        Err(quinn::ConnectError::UnsupportedVersion)
    ));
}

/// The application settings the server of [alps_in_handshake_data] sends for h3.
const SERVER_ALPS: &[u8] = b"\x40\x89\x0cserver alps!";

/// Makes the server send [SERVER_ALPS] for h3, under the codepoint Chrome uses: ALPS is a setting
/// of each SSL, and the quinn-btls server creates them itself.
extern "C" fn add_server_alps(
    client_hello: *const bffi::SSL_CLIENT_HELLO,
) -> bffi::ssl_select_cert_result_t {
    let ssl = unsafe { (*client_hello).ssl };
    unsafe {
        bffi::SSL_set_alps_use_new_codepoint(ssl, 1);
        let ret = bffi::SSL_add_application_settings(
            ssl,
            b"h3".as_ptr(),
            2,
            SERVER_ALPS.as_ptr(),
            SERVER_ALPS.len(),
        );
        assert_eq!(ret, 1);
    }
    bffi::ssl_select_cert_result_t::ssl_select_cert_success
}

/// HandshakeData carries the peer's ALPS application settings if ALPS was negotiated.
#[tokio::test]
async fn alps_in_handshake_data() {
    let (cert, key) = self_signed_certificate();
    let mut server_crypto = ServerConfig::new().unwrap();
    server_crypto
        .ctx_mut()
        .set_select_certificate_cb(Some(add_server_alps));
    let server = server_endpoint(cert.clone(), key, server_crypto);
    let server_addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(run_echo_server(server, 2));

    // With ALPS offered for h3 (empty client settings, as Chrome sends them) and without.
    let mut seen = Vec::new();
    for alps in [true, false] {
        let mut crypto = ClientConfig::from_builder(client_builder(&cert)).unwrap();
        if alps {
            crypto.set_configure_connection_callback(|ssl, _, _| {
                ssl.set_alps_use_new_codepoint(true);
                ssl.add_application_settings(b"h3")?;
                Ok(())
            });
        }
        let client = client_endpoint(crypto);
        let conn = client.connect(server_addr, SERVER_NAME).unwrap();
        let conn = tokio::time::timeout(Duration::from_secs(10), conn)
            .await
            .expect("handshake timed out")
            .unwrap();
        assert_eq!(echo(&conn, b"alps").await, b"alps");
        seen.push(handshake_data(&conn).peer_application_settings);
        conn.close(0u32.into(), b"done");
        client.wait_idle().await;
    }
    assert_eq!(seen, [Some(SERVER_ALPS.to_vec()), None]);

    let server_seen = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server timed out")
        .unwrap();
    let server_seen: Vec<_> = server_seen
        .into_iter()
        .map(|data| data.peer_application_settings)
        .collect();
    assert_eq!(server_seen, [Some(Vec::new()), None]);
}

/// Two concurrent connections built from the same shared [ClientConfig], each wrapped in its own
/// [PerConnectionConfig] with a different per-connection callback, must not race on or overwrite
/// each other's configuration: no state about either connection's callback is kept anywhere but
/// its own `PerConnectionConfig`, unlike a host-keyed map [ClientConfig::set_configure_connection_callback]
/// alone would need for the same purpose.
#[tokio::test]
async fn per_connection_config_is_isolated_between_concurrent_connections() {
    let (cert, key) = self_signed_certificate();
    let mut server_crypto = ServerConfig::new().unwrap();
    server_crypto
        .ctx_mut()
        .set_select_certificate_cb(Some(add_server_alps));
    let server = server_endpoint(cert.clone(), key, server_crypto);
    let server_addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(run_echo_server(server, 2));

    // One shared Config (one SSL_CTX, built once), as an HTTP client shares one across all of its
    // connections.
    let shared = Arc::new(ClientConfig::from_builder(client_builder(&cert)).unwrap());
    let endpoint = helpers::client_endpoint((Ipv4Addr::LOCALHOST, 0).into()).unwrap();

    let with_alps = PerConnectionConfig::new(shared.clone(), |ssl, _, _| {
        ssl.set_alps_use_new_codepoint(true);
        ssl.add_application_settings(b"h3")?;
        Ok(())
    });
    let without_alps = PerConnectionConfig::new(shared.clone(), |_, _, _| Ok(()));

    // Both connect_with calls are made, and both handshakes driven, before either finishes: a
    // host-keyed map keyed only by `SERVER_NAME` (both connections use the same one) would have
    // one callback invocation overwrite or race with the other's entry.
    let conn_with_alps = endpoint
        .connect_with(
            quinn::ClientConfig::new(Arc::new(with_alps)),
            server_addr,
            SERVER_NAME,
        )
        .unwrap();
    let conn_without_alps = endpoint
        .connect_with(
            quinn::ClientConfig::new(Arc::new(without_alps)),
            server_addr,
            SERVER_NAME,
        )
        .unwrap();
    let (conn_with_alps, conn_without_alps) =
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(conn_with_alps, conn_without_alps)
        })
        .await
        .expect("handshake timed out");
    let conn_with_alps = conn_with_alps.unwrap();
    let conn_without_alps = conn_without_alps.unwrap();

    assert_eq!(
        handshake_data(&conn_with_alps).peer_application_settings,
        Some(SERVER_ALPS.to_vec())
    );
    assert_eq!(
        handshake_data(&conn_without_alps).peer_application_settings,
        None
    );
    assert_eq!(echo(&conn_with_alps, b"with").await, b"with");
    assert_eq!(echo(&conn_without_alps, b"without").await, b"without");
    conn_with_alps.close(0u32.into(), b"done");
    conn_without_alps.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    let server_seen = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server timed out")
        .unwrap();
    let with_alps_count = server_seen
        .iter()
        .filter(|data| data.peer_application_settings == Some(Vec::new()))
        .count();
    let without_alps_count = server_seen
        .iter()
        .filter(|data| data.peer_application_settings.is_none())
        .count();
    assert_eq!((with_alps_count, without_alps_count), (1, 1));
}

// For future reference, these configs are generated by building the bssl tool (the binary is
// built alongside boringssl) and running:
// ./bssl generate-ech -out-ech-config-list ./list -out-ech-config ./config -out-private-key ./key
// -public-name ech.com -config-id 1
static ECH_CONFIG: &[u8] = include_bytes!("../../btls/test/echconfig");
static ECH_KEY: &[u8] = include_bytes!("../../btls/test/echkey");
static ECH_CONFIG_LIST: &[u8] = include_bytes!("../../btls/test/echconfiglist");

/// A real (non-GREASE) ECH handshake over QUIC, with a distinct, reduced ClientHelloOuter
/// transport-parameters value (`SSL_set_quic_transport_params_outer`, `PerConnectionConfig`'s own
/// reason to exist). Checks: the connection establishes and behaves as if the server used the
/// *inner* transport parameters (not the outer's, which lack stream limits and so would leave no
/// bidirectional stream to open at all), and the wire's outer `quic_transport_parameters`
/// extension carries exactly the configured outer bytes, not the real (inner) ones.
///
/// The client's raw Initial packet is decrypted independently (Initial protection keys derive
/// from the destination connection ID alone, RFC 9001 §5.2, not from anything btls keeps secret)
/// instead of reading it back from btls's own `select_certificate_cb`: once ECH is accepted, that
/// callback's `SSL_CLIENT_HELLO` reflects the reconstructed ClientHelloInner, not the bytes
/// actually on the wire, which is exactly the outer/inner distinction this test exists to check.
#[tokio::test]
async fn ech_outer_transport_params_are_on_the_wire_and_the_server_uses_the_inner_ones() {
    let (cert, key) = self_signed_certificate();

    let mut server_crypto = ServerConfig::new().unwrap();
    server_crypto
        .ctx_mut()
        .set_certificate(cert.clone())
        .unwrap();
    server_crypto.ctx_mut().set_private_key(key).unwrap();
    let hpke_key = HpkeKey::dhkem_p256_sha256(ECH_KEY).unwrap();
    let mut ech_keys_builder = SslEchKeys::builder().unwrap();
    ech_keys_builder
        .add_key(true, ECH_CONFIG, hpke_key)
        .unwrap();
    server_crypto
        .ctx_mut()
        .set_ech_keys(&ech_keys_builder.build())
        .unwrap();
    let config = helpers::server_config(Arc::new(server_crypto)).unwrap();
    let server = helpers::server_endpoint(config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(run_echo_server(server, 1));
    let relay = Relay::start(server_addr, Duration::ZERO).await;

    let shared = Arc::new(ClientConfig::from_builder(client_builder(&cert)).unwrap());
    let outer_seen: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let outer_seen_clone = outer_seen.clone();
    let per_connection = PerConnectionConfig::new(shared, move |ssl, _host, params| {
        ssl.set_ech_config_list(ECH_CONFIG_LIST)?;
        let mut outer = Vec::new();
        params.write_ech_outer(&mut outer);
        ssl.set_quic_transport_params_outer(&outer)?;
        *outer_seen_clone.lock().unwrap() = Some(outer);
        Ok(())
    });
    let endpoint = helpers::client_endpoint((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let conn = endpoint
        .connect_with(
            quinn::ClientConfig::new(Arc::new(per_connection)),
            relay.addr,
            SERVER_NAME,
        )
        .unwrap();
    let conn = tokio::time::timeout(Duration::from_secs(10), conn)
        .await
        .expect("handshake timed out")
        .unwrap();

    // The reduced outer transport parameters (max_ack_delay, initial_src_cid,
    // version_information only) carry no stream limits, which RFC 9000 defaults to zero when
    // absent: opening a bidirectional stream would hang or fail if the server had negotiated
    // with them instead of the real, inner ones.
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), echo(&conn, b"ech"))
            .await
            .expect("echo timed out"),
        b"ech"
    );
    conn.close(0u32.into(), b"done");

    tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .expect("server timed out")
        .unwrap();
    endpoint.wait_idle().await;

    // Decrypt the client's Initial packet(s) off the wire and reassemble its CRYPTO frames into
    // the real ClientHelloOuter, exactly as sent (the relay makes no changes, only forwards).
    let mut crypto_frames = Vec::new();
    for datagram in relay.client_datagrams() {
        if let Some(frames) = open_initial(&datagram) {
            crypto_frames.extend(frames);
        }
    }
    let hello = reassemble_crypto(&crypto_frames).expect("a complete ClientHello");
    assert_eq!(hello[0], 0x01, "ClientHello handshake message");
    let hello = ClientHello::parse(&hello[4..]);

    let outer = outer_seen.lock().unwrap().clone().unwrap();
    assert_eq!(
        hello.extension(TLSEXT_QUIC_TRANSPORT_PARAMETERS),
        &outer[..]
    );
}

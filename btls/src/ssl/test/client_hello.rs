//! Captures the ClientHellos a client sends and tests options that shape them.

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use crate::hpke::HpkeAead;
use crate::ssl::test::server::Server;
use crate::ssl::{
    ExtensionType, Ssl, SslContext, SslContextBuilder, SslMethod, SslRef, SslSessionCacheMode,
    SslSignatureAlgorithm, SslVersion,
};

const TLSEXT_SUPPORTED_GROUPS: u16 = 10;
const TLSEXT_SIGNATURE_ALGORITHMS: u16 = 13;
const TLSEXT_PADDING: u16 = 21;
const TLSEXT_EXTENDED_MASTER_SECRET: u16 = 23;
const TLSEXT_DELEGATED_CREDENTIAL: u16 = 34;
const TLSEXT_SUPPORTED_VERSIONS: u16 = 43;
const TLSEXT_PRE_SHARED_KEY: u16 = 41;
const TLSEXT_KEY_SHARE: u16 = 51;
const TLSEXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const TLSEXT_RENEGOTIATE: u16 = 0xff01;

const HPKE_HKDF_SHA256: u16 = 1;
const HPKE_AES_128_GCM: u16 = 1;
const HPKE_CHACHA20_POLY1305: u16 = 3;
/// The payload lengths BoringSSL draws from for ECH GREASE by default: 128 to 224 bytes in steps
/// of 32, plus the 16-byte tag of either AEAD.
const DEFAULT_ECH_GREASE_PAYLOAD_LENS: [usize; 4] = [144, 176, 208, 240];

/// A client stream that keeps a copy of every byte the client sends.
#[derive(Debug)]
struct RecordingStream {
    inner: TcpStream,
    sent: Arc<Mutex<Vec<u8>>>,
}

impl Read for RecordingStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for RecordingStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.sent.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(super) struct ClientHello {
    pub(super) cipher_suites: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl ClientHello {
    fn find(&self, ext_type: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(t, _)| *t == ext_type)
            .map(|(_, data)| &data[..])
    }

    fn extension(&self, ext_type: u16) -> &[u8] {
        self.find(ext_type)
            .unwrap_or_else(|| panic!("extension {ext_type:#06x} missing"))
    }

    fn has_extension(&self, ext_type: u16) -> bool {
        self.find(ext_type).is_some()
    }

    pub(super) fn signature_algorithms(&self) -> Vec<u16> {
        u16_list(&self.extension(TLSEXT_SIGNATURE_ALGORITHMS)[2..])
    }

    pub(super) fn supported_groups(&self) -> Vec<u16> {
        u16_list(&self.extension(TLSEXT_SUPPORTED_GROUPS)[2..])
    }

    pub(super) fn supported_versions(&self) -> Vec<u16> {
        u16_list(&self.extension(TLSEXT_SUPPORTED_VERSIONS)[1..])
    }

    pub(super) fn extension_types(&self) -> Vec<u16> {
        self.extensions.iter().map(|(t, _)| *t).collect()
    }

    /// The extension types without padding, which BoringSSL adds depending on the length.
    fn extension_types_without_padding(&self) -> Vec<u16> {
        let mut types = self.extension_types();
        types.retain(|t| *t != TLSEXT_PADDING);
        types
    }

    fn ech_outer(&self) -> EchOuter {
        let mut ext = Reader(self.extension(TLSEXT_ENCRYPTED_CLIENT_HELLO));
        assert_eq!(ext.u8(), 0, "not an outer ECH extension");
        let kdf = ext.u16() as u16;
        let aead = ext.u16() as u16;
        ext.u8(); // config_id
        let len = ext.u16();
        let enc_len = ext.take(len).len();
        let len = ext.u16();
        let payload_len = ext.take(len).len();
        assert!(ext.0.is_empty());
        EchOuter {
            kdf,
            aead,
            enc_len,
            payload_len,
        }
    }
}

/// The fields of an outer encrypted_client_hello extension that GREASE shapes.
struct EchOuter {
    kdf: u16,
    aead: u16,
    enc_len: usize,
    payload_len: usize,
}

pub(super) fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

pub(super) fn grease_values(values: &[u16]) -> Vec<u16> {
    values.iter().copied().filter(|v| is_grease(*v)).collect()
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

    fn u24(&mut self) -> usize {
        let b = self.take(3);
        u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize
    }
}

/// Extracts every ClientHello from the bytes a client sent. Handshake records are only in
/// plaintext until the ServerHello, so with TLS 1.3 these are the initial ClientHello and, after
/// a HelloRetryRequest, the second one.
fn parse_client_hellos(sent: &[u8]) -> Vec<ClientHello> {
    let mut handshake = Vec::new();
    let mut records = Reader(sent);
    while !records.0.is_empty() {
        let content_type = records.u8();
        records.take(2);
        let len = records.u16();
        let fragment = records.take(len);
        if content_type == 22 {
            handshake.extend_from_slice(fragment);
        }
    }

    let mut hellos = Vec::new();
    let mut messages = Reader(&handshake);
    while !messages.0.is_empty() {
        let msg_type = messages.u8();
        let len = messages.u24();
        let mut body = Reader(messages.take(len));
        if msg_type != 1 {
            continue;
        }

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

        hellos.push(ClientHello {
            cipher_suites,
            extensions,
        });
    }
    hellos
}

/// Connects to `server` with an `Ssl` from `ctx`, prepared by `configure`, and returns the
/// ClientHellos the client sent.
pub(super) fn client_hellos(
    server: &Server,
    ctx: &SslContext,
    configure: impl FnOnce(&mut SslRef),
) -> Vec<ClientHello> {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let stream = RecordingStream {
        inner: server.connect_tcp(),
        sent: sent.clone(),
    };
    let mut ssl = Ssl::new(ctx).unwrap();
    configure(&mut ssl);
    let mut stream = ssl.connect(stream).unwrap();
    stream.read_exact(&mut [0]).unwrap();

    let sent = sent.lock().unwrap();
    parse_client_hellos(&sent)
}

pub(super) fn single_client_hello(server: &Server, ctx: &SslContext) -> ClientHello {
    single_client_hello_with(server, ctx, |_| {})
}

fn single_client_hello_with(
    server: &Server,
    ctx: &SslContext,
    configure: impl FnOnce(&mut SslRef),
) -> ClientHello {
    let mut hellos = client_hellos(server, ctx, configure);
    assert_eq!(hellos.len(), 1, "expected a single ClientHello");
    hellos.pop().unwrap()
}

pub(super) fn client_ctx(configure: impl FnOnce(&mut SslContextBuilder)) -> SslContext {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    configure(&mut ctx);
    ctx.build()
}

#[test]
fn tls13_legacy_extensions() {
    let mut server = Server::builder();
    server.expected_connections_count(3);
    let server = server.build();

    let tls13_only = |ctx: &mut SslContextBuilder| {
        ctx.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    };

    // A client that also offers TLS 1.2 needs both.
    let hello = single_client_hello(&server, &client_ctx(|_| {}));
    assert!(hello.has_extension(TLSEXT_EXTENDED_MASTER_SECRET));
    assert!(hello.has_extension(TLSEXT_RENEGOTIATE));

    let hello = single_client_hello(&server, &client_ctx(tls13_only));
    assert!(!hello.has_extension(TLSEXT_EXTENDED_MASTER_SECRET));
    assert!(!hello.has_extension(TLSEXT_RENEGOTIATE));

    let ctx = client_ctx(|ctx| {
        tls13_only(ctx);
        ctx.set_tls13_legacy_extensions(true);
    });
    let hello = single_client_hello(&server, &ctx);
    assert_eq!(hello.supported_versions(), [0x0304]);
    assert_eq!(hello.extension(TLSEXT_EXTENDED_MASTER_SECRET), b"");
    // An empty renegotiated_connection: this is the initial handshake.
    assert_eq!(hello.extension(TLSEXT_RENEGOTIATE), b"\x00");
}

#[test]
fn extension_order_tail() {
    const CONNECTIONS: usize = 8;

    let mut server = Server::builder();
    server.expected_connections_count(CONNECTIONS + 2);
    let server = server.build();

    // Two extensions every ClientHello carries, against their default order, and one this
    // library does not know, which is skipped.
    let tail = [
        ExtensionType::KEY_SHARE,
        ExtensionType::from(0x1234),
        ExtensionType::SIGNATURE_ALGORITHMS,
    ];
    let expected_tail = [TLSEXT_KEY_SHARE, TLSEXT_SIGNATURE_ALGORITHMS];

    // Without a permutation, the other extensions keep the default order.
    let plain = single_client_hello(&server, &client_ctx(|_| {})).extension_types_without_padding();
    let mut expected: Vec<u16> = plain
        .iter()
        .copied()
        .filter(|t| !expected_tail.contains(t))
        .collect();
    expected.extend(expected_tail);
    let ctx = client_ctx(|ctx| ctx.set_extension_order_tail(&tail).unwrap());
    let hello = single_client_hello(&server, &ctx);
    assert_eq!(hello.extension_types_without_padding(), expected);

    // With a permutation, the other extensions are shuffled on every connection, the tail stays.
    let ctx = client_ctx(|ctx| {
        ctx.set_permute_extensions(true);
        ctx.set_extension_order_tail(&tail).unwrap();
    });
    let mut plain_sorted = plain.clone();
    plain_sorted.sort_unstable();
    let mut orders = HashSet::new();
    for _ in 0..CONNECTIONS {
        let types = single_client_hello(&server, &ctx).extension_types_without_padding();
        assert_eq!(types[types.len() - 2..], expected_tail, "{types:04x?}");
        let mut sorted = types.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, plain_sorted);
        orders.insert(types);
    }
    assert!(orders.len() > 1, "same extension order on every connection");
}

/// A tail for [extension_order_tail_with_resumption] and
/// [extension_order_tail_after_hello_retry_request], and the extensions it puts at the end.
const TAIL: [ExtensionType; 2] = [
    ExtensionType::KEY_SHARE,
    ExtensionType::SIGNATURE_ALGORITHMS,
];
const EXPECTED_TAIL: [u16; 2] = [TLSEXT_KEY_SHARE, TLSEXT_SIGNATURE_ALGORITHMS];

/// When the client offers a session, pre_shared_key, which has to be the last extension, follows
/// the tail.
#[test]
fn extension_order_tail_with_resumption() {
    let mut server = Server::builder();
    server.expected_connections_count(2);
    let server = server.build();

    let session = Arc::new(Mutex::new(None));
    let stored = session.clone();
    let ctx = client_ctx(|ctx| {
        ctx.set_permute_extensions(true);
        ctx.set_extension_order_tail(&TAIL).unwrap();
        ctx.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        ctx.set_new_session_callback(move |_, session| {
            stored.lock().unwrap().get_or_insert(session);
        });
    });

    let full = single_client_hello(&server, &ctx);
    let session = session.lock().unwrap().take().expect("no session ticket");
    assert_eq!(session.protocol_version(), SslVersion::TLS1_3);
    let resumed = single_client_hello_with(&server, &ctx, |ssl| unsafe {
        ssl.set_session(&session).unwrap()
    });

    let types = full.extension_types_without_padding();
    assert!(!types.contains(&TLSEXT_PRE_SHARED_KEY), "{types:04x?}");
    assert!(types.ends_with(&EXPECTED_TAIL), "{types:04x?}");
    let types = resumed.extension_types_without_padding();
    assert!(
        types.ends_with(&[EXPECTED_TAIL[0], EXPECTED_TAIL[1], TLSEXT_PRE_SHARED_KEY]),
        "{types:04x?}"
    );
}

/// The second ClientHello after a HelloRetryRequest keeps the extensions in the order of the
/// first, the tail included.
#[test]
fn extension_order_tail_after_hello_retry_request() {
    // The client predicts an X25519 key share, the server only accepts P-256, which forces a
    // HelloRetryRequest and a second ClientHello.
    let mut server = Server::builder();
    server.ctx().set_curves_list("P-256").unwrap();
    let server = server.build();

    let ctx = client_ctx(|ctx| {
        ctx.set_curves_list("X25519:P-256").unwrap();
        ctx.set_permute_extensions(true);
        ctx.set_extension_order_tail(&TAIL).unwrap();
    });
    let hellos = client_hellos(&server, &ctx, |_| {});
    let [first, second] = &hellos[..] else {
        panic!(
            "expected a HelloRetryRequest, got {} ClientHellos",
            hellos.len()
        );
    };

    let types = first.extension_types_without_padding();
    assert!(types.ends_with(&EXPECTED_TAIL), "{types:04x?}");
    assert_eq!(second.extension_types_without_padding(), types);
}

#[test]
fn ech_grease_params() {
    const CONNECTIONS: usize = 8;

    let mut server = Server::builder();
    server.expected_connections_count(CONNECTIONS + 3);
    let server = server.build();
    let ctx = client_ctx(|_| {});

    // BoringSSL's defaults: the AEAD follows the AES hardware support, the payload length is
    // drawn per connection.
    let ech =
        single_client_hello_with(&server, &ctx, |ssl| ssl.set_enable_ech_grease(true)).ech_outer();
    assert_eq!(ech.kdf, HPKE_HKDF_SHA256);
    assert!([HPKE_AES_128_GCM, HPKE_CHACHA20_POLY1305].contains(&ech.aead));
    assert_eq!(ech.enc_len, 32);
    assert!(DEFAULT_ECH_GREASE_PAYLOAD_LENS.contains(&ech.payload_len));

    // Firefox: ChaCha20-Poly1305 and a payload sized like its ClientHelloInner.
    for payload_len in [240, 528] {
        let ech = single_client_hello_with(&server, &ctx, |ssl| {
            ssl.set_enable_ech_grease(true);
            ssl.set_ech_grease_aead(HpkeAead::CHACHA20_POLY1305)
                .unwrap();
            ssl.set_ech_grease_payload_len(payload_len);
        })
        .ech_outer();
        assert_eq!(ech.kdf, HPKE_HKDF_SHA256);
        assert_eq!(ech.aead, HPKE_CHACHA20_POLY1305);
        assert_eq!(ech.enc_len, 32);
        assert_eq!(ech.payload_len, usize::from(payload_len));
    }

    // Chrome: AES-128-GCM whatever the hardware, with the default random payload length.
    let mut payload_lens = HashSet::new();
    for _ in 0..CONNECTIONS {
        let ech = single_client_hello_with(&server, &ctx, |ssl| {
            ssl.set_enable_ech_grease(true);
            ssl.set_ech_grease_aead(HpkeAead::AES_128_GCM).unwrap();
        })
        .ech_outer();
        assert_eq!(ech.aead, HPKE_AES_128_GCM);
        assert!(DEFAULT_ECH_GREASE_PAYLOAD_LENS.contains(&ech.payload_len));
        payload_lens.insert(ech.payload_len);
    }
    assert!(
        payload_lens.len() > 1,
        "same payload length {payload_lens:?} every time"
    );

    let mut ssl = Ssl::new(&ctx).unwrap();
    assert!(ssl.set_ech_grease_aead(HpkeAead::from_raw(0x1234)).is_err());
}

#[test]
fn delegated_credential_algorithm_prefs() {
    // Firefox's list over QUIC: the ML-DSA schemes at the end are unknown to BoringSSL.
    const PREFS: [u16; 7] = [0x0403, 0x0503, 0x0603, 0x0203, 0x0904, 0x0905, 0x0906];

    let mut server = Server::builder();
    server.expected_connections_count(2);
    let server = server.build();

    let prefs: Vec<SslSignatureAlgorithm> = PREFS.iter().copied().map(Into::into).collect();
    let ctx = client_ctx(|ctx| {
        ctx.set_delegated_credential_algorithm_prefs(&prefs)
            .unwrap()
    });
    let hello = single_client_hello(&server, &ctx);
    assert_eq!(
        u16_list(&hello.extension(TLSEXT_DELEGATED_CREDENTIAL)[2..]),
        PREFS
    );

    // An empty list turns the extension off again.
    let ctx = client_ctx(|ctx| {
        ctx.set_delegated_credential_algorithm_prefs(&prefs)
            .unwrap();
        ctx.set_delegated_credential_algorithm_prefs(&[]).unwrap();
    });
    let hello = single_client_hello(&server, &ctx);
    assert!(!hello.has_extension(TLSEXT_DELEGATED_CREDENTIAL));
}

/// server_padding carries the number of bytes the client asks for. A server that answers sends
/// exactly those in EncryptedExtensions, one that does not ignores the extension; the client
/// tells the two apart.
#[test]
fn server_padding() {
    const TLSEXT_SERVER_PADDING: u16 = 0x12e0;

    let mut server = Server::builder();
    server.expected_connections_count(2);
    let server = server.build();
    let ctx = client_ctx(|_| {});
    let hello = single_client_hello(&server, &ctx);
    assert!(!hello.has_extension(TLSEXT_SERVER_PADDING));
    let hello = single_client_hello_with(&server, &ctx, |ssl| {
        ssl.set_server_padding_request(4000);
    });
    assert_eq!(
        hello.extension(TLSEXT_SERVER_PADDING),
        4000u16.to_be_bytes()
    );

    for enabled in [false, true] {
        let mut server = Server::builder();
        server.ssl_cb(move |ssl| ssl.set_server_padding_enabled(enabled));
        let server = server.build();
        let mut client = server.client().build().builder();
        client.ssl().set_server_padding_request(4000);
        let stream = client.connect();
        assert_eq!(stream.ssl().server_sent_requested_padding(), enabled);
    }
}

#![allow(unused)]
mod aead;
mod alert;
mod alpn;
mod bffi_ext;
mod client;
mod error;
mod handshake_token;
mod hkdf;
mod hmac;
mod key;
mod macros;
mod retry;
mod secret;
mod server;
mod session_cache;
mod session_state;
mod suite;
mod version;

// Export the public interface.
pub use bffi_ext::*;
pub use client::{Config as ClientConfig, PerConnectionConfig};
pub use error::{Error, Result};
pub use handshake_token::HandshakeTokenKey;
pub use hmac::HmacKey;
/// Re-exported so callers of [ClientConfig::set_configure_connection_callback] can name the
/// callback's transport-parameters argument.
pub use quinn_proto::transport_parameters::TransportParameters;
pub use server::Config as ServerConfig;
pub use session_cache::*;
pub use version::QuicVersion;

/// Information available from [quinn_proto::crypto::Session::handshake_data]: once the
/// application protocol (or on a server, the server name) is known, and after the handshake in
/// any case.
///
/// More fields may be added, so it cannot be built outside of this crate.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct HandshakeData {
    /// The negotiated application protocol, if ALPN is in use
    ///
    /// Guaranteed to be set if a nonempty list of protocols was specified for this connection.
    pub protocol: Option<Vec<u8>>,

    /// The server name specified by the client, if any
    ///
    /// Always `None` for outgoing connections
    pub server_name: Option<String>,

    /// Whether the TLS handshake resumed a previous session
    pub session_reused: bool,

    /// The application settings the peer sent for the negotiated protocol, if ALPS was
    /// negotiated, e.g. the ACCEPT_CH frame of Google's HTTP/3 servers
    ///
    /// A client has them together with the protocol, a server once the handshake is complete.
    pub peer_application_settings: Option<Vec<u8>>,
}

pub mod helpers {
    use super::*;
    use quinn_proto::crypto;
    use std::sync::Arc;

    /// Create a server config with the given [`crypto::ServerConfig`]
    ///
    /// Uses a randomized handshake token key.
    pub fn server_config(crypto: Arc<dyn crypto::ServerConfig>) -> Result<quinn::ServerConfig> {
        Ok(quinn::ServerConfig::new(
            crypto,
            Arc::new(HandshakeTokenKey::new()?),
        ))
    }

    /// Returns a default endpoint configuration for BoringSSL.
    pub fn default_endpoint_config() -> quinn::EndpointConfig {
        let mut cfg = quinn::EndpointConfig::new(Arc::new(HmacKey::sha256()));
        cfg.supported_versions(QuicVersion::default_supported_versions());
        cfg
    }

    /// Helper to construct an endpoint for use with outgoing connections only
    ///
    /// Note that `addr` is the *local* address to bind to, which should usually be a wildcard
    /// address like `0.0.0.0:0` or `[::]:0`, which allow communication with any reachable IPv4 or
    /// IPv6 address respectively from an OS-assigned port.
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket bound to a wildcard
    /// IPv6 address on Windows will not by default be able to communicate with IPv4
    /// addresses. Portable applications should bind an address that matches the family they wish to
    /// communicate within.
    #[cfg(feature = "runtime-tokio")]
    pub fn client_endpoint(addr: std::net::SocketAddr) -> std::io::Result<quinn::Endpoint> {
        let socket = std::net::UdpSocket::bind(addr)?;
        quinn::Endpoint::new(
            default_endpoint_config(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
    }

    /// Helper to construct an endpoint for use with both incoming and outgoing connections
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket bound to a wildcard
    /// IPv6 address on Windows will not by default be able to communicate with IPv4
    /// addresses. Portable applications should bind an address that matches the family they wish to
    /// communicate within.
    #[cfg(feature = "runtime-tokio")]
    pub fn server_endpoint(
        config: quinn::ServerConfig,
        addr: std::net::SocketAddr,
    ) -> std::io::Result<quinn::Endpoint> {
        let socket = std::net::UdpSocket::bind(addr)?;
        quinn::Endpoint::new(
            default_endpoint_config(),
            Some(config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::error::Result;
    use crate::secret::{Secret, Secrets};
    use crate::suite::CipherSuite;
    use bytes::BytesMut;
    use hex_literal::hex;
    use quinn_proto::crypto::{self, PacketKey};
    use quinn_proto::{ConnectionId, Side};

    /// Copied from quiche.
    #[test]
    fn test_initial_keys_v1() -> Result<()> {
        let dcid: &[u8] = &hex!("8394c8f03e515708");
        let version = QuicVersion::V1;
        let suite = CipherSuite::aes128_gcm_sha256();

        let s = Secrets::initial(version, &ConnectionId::new(dcid), Side::Client)?;

        let expected_enc_key: &[u8] = &hex!("1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(
            s.local.packet_key(version, suite)?.key().slice(),
            expected_enc_key
        );
        let expected_enc_iv: &[u8] = &hex!("fa044b2f42a3fd3b46fb255c");
        assert_eq!(
            s.local.packet_key(version, suite)?.iv().slice(),
            expected_enc_iv
        );
        let expected_enc_hdr_key: &[u8] = &hex!("9f50449e04a0e810283a1e9933adedd2");
        assert_eq!(
            s.local.header_key(version, suite)?.key().slice(),
            expected_enc_hdr_key
        );
        let expected_dec_key: &[u8] = &hex!("cf3a5331653c364c88f0f379b6067e37");
        assert_eq!(
            s.remote.packet_key(version, suite)?.key().slice(),
            expected_dec_key
        );
        let expected_dec_iv: &[u8] = &hex!("0ac1493ca1905853b0bba03e");
        assert_eq!(
            s.remote.packet_key(version, suite)?.iv().slice(),
            expected_dec_iv
        );
        let expected_dec_hdr_key: &[u8] = &hex!("c206b8d9b9f0f37644430b490eeaa314");
        assert_eq!(
            s.remote.header_key(version, suite)?.key().slice(),
            expected_dec_hdr_key
        );

        Ok(())
    }

    /// Copied from rustls.
    #[test]
    fn short_packet_header_protection() {
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-chacha20-poly1305-short-hea

        const PN: u64 = 654360564;
        const SECRET: &[u8] =
            &hex!("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");

        let version = QuicVersion::V1;
        let suite = CipherSuite::chacha20_poly1305_sha256();

        let secret = Secret::from(SECRET);
        let hpk = secret
            .header_key(version, suite)
            .unwrap()
            .as_crypto()
            .unwrap();
        let packet = secret.packet_key(version, suite).unwrap();

        const PLAIN: &[u8] = &[0x42, 0x00, 0xbf, 0xf4, b'h', b'e', b'l', b'l', b'o'];

        let mut buf = PLAIN.to_vec();
        // Make space for the output tag.
        buf.extend_from_slice(&[0u8; 16]);
        packet.encrypt(PN, &mut buf, 4);

        let pn_offset = 1;
        hpk.encrypt(pn_offset, &mut buf);

        const PROTECTED: &[u8] = &hex!("593b46220c4d504a9f1857793356400fc4a784ee309dff98b2");

        assert_eq!(&buf, PROTECTED);

        hpk.decrypt(pn_offset, &mut buf);

        let (header, payload_tag) = buf.split_at(4);
        let mut payload_tag = BytesMut::from(payload_tag);
        packet.decrypt(PN, header, &mut payload_tag).unwrap();
        let plain = payload_tag.as_ref();
        assert_eq!(plain, &PLAIN[4..]);
    }

    /// Copied from rustls.
    #[test]
    fn key_update_test_vector() {
        let version = QuicVersion::V1;
        let suite = CipherSuite::aes128_gcm_sha256();
        let mut secrets = Secrets {
            version,
            suite,
            local: Secret::from(&hex!(
                "b8767708f8772358a6ea9fc43e4add2c961b3f5287a6d1467ee0aeab33724dbf"
            )),
            remote: Secret::from(&hex!(
                "42dc972140e0f2e39845b767613439dc6758ca43259b878506824eb1e438d855"
            )),
        };
        secrets.update().unwrap();

        let expected = Secrets {
            version,
            suite,
            local: Secret::from(&hex!(
                "42cac8c91cd5eb40682e432edf2d2be9f41a52ca6b22d8e6cdb1e8aca9061fce"
            )),
            remote: Secret::from(&hex!(
                "eb7f5e2a123f407db499e361cae590d4d992e14b7ace03c244e0422115b6d38a"
            )),
        };

        assert_eq!(expected, secrets);
    }

    #[test]
    fn client_encrypt_header() {
        let dcid = ConnectionId::new(&hex!("06b858ec6f80452b"));

        let secrets = Secrets::initial(QuicVersion::V1, &dcid, Side::Client).unwrap();
        let client = secrets.keys().unwrap().as_crypto().unwrap();

        // Client (encrypt)
        let mut packet: [u8; 51] = hex!(
            "c0000000010806b858ec6f80452b0000402100c8fb7ffd97230e38b70d86e7ff148afdf88fc21c4426c7d1cec79914c8785757"
        );
        let packet_number = 0;
        let packet_number_pos = 18;
        let header_len = 19;

        // Encrypt the payload.
        client
            .packet
            .local
            .encrypt(packet_number, &mut packet, header_len);
        let expected_after_packet_encrypt: [u8; 51] = hex!(
            "c0000000010806b858ec6f80452b0000402100f60e77fa2f629f9921fae64125c5632cf769d801a4693af6b949af37c2c45399"
        );
        assert_eq!(packet, expected_after_packet_encrypt);

        // Encrypt the header.
        client.header.local.encrypt(packet_number_pos, &mut packet);
        let expected_after_header_encrypt: [u8; 51] = hex!(
            "cd000000010806b858ec6f80452b000040210bf60e77fa2f629f9921fae64125c5632cf769d801a4693af6b949af37c2c45399"
        );
        assert_eq!(packet, expected_after_header_encrypt);
    }

    #[test]
    fn server_decrypt_header() {
        let dcid = ConnectionId::new(&hex!("06b858ec6f80452b"));
        let secrets = Secrets::initial(QuicVersion::V1, &dcid, Side::Server).unwrap();
        let server = secrets.keys().unwrap().as_crypto().unwrap();

        let mut packet = BytesMut::from(
            &hex!(
                "c8000000010806b858ec6f80452b00004021be3ef50807b84191a196f760a6dad1e9d1c430c48952cba0148250c21c0a6a70e1"
            )[..],
        );
        let packet_number = 0;
        let packet_number_pos = 18;
        let header_len = 19;

        // Decrypt the header.
        server.header.remote.decrypt(packet_number_pos, &mut packet);
        let expected_header: [u8; 19] = hex!("c0000000010806b858ec6f80452b0000402100");
        assert_eq!(packet[..header_len], expected_header);

        // Decrypt the payload.
        let mut header = packet;
        let mut packet = header.split_off(header_len);
        server
            .packet
            .remote
            .decrypt(packet_number, &header, &mut packet)
            .unwrap();
        assert_eq!(packet[..], [0; 16]);
    }

    /// RFC 9369, appendix A.1.
    #[test]
    fn test_initial_keys_v2() -> Result<()> {
        let dcid = ConnectionId::new(&hex!("8394c8f03e515708"));
        let version = QuicVersion::V2;
        let suite = CipherSuite::aes128_gcm_sha256();

        let s = Secrets::initial(version, &dcid, Side::Client)?;
        assert_eq!(
            s.local.slice(),
            hex!("14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b")
        );
        assert_eq!(
            s.remote.slice(),
            hex!("0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1")
        );

        let client = s.local.packet_key(version, suite)?;
        assert_eq!(
            client.key().slice(),
            hex!("8b1a0bc121284290a29e0971b5cd045d")
        );
        assert_eq!(client.iv().slice(), hex!("91f73e2351d8fa91660e909f"));
        assert_eq!(
            s.local.header_key(version, suite)?.key().slice(),
            hex!("45b95e15235d6f45a6b19cbcb0294ba9")
        );
        let server = s.remote.packet_key(version, suite)?;
        assert_eq!(
            server.key().slice(),
            hex!("82db637861d55e1d011f19ea71d5d2a7")
        );
        assert_eq!(server.iv().slice(), hex!("dd13c276499c0249d3310652"));
        assert_eq!(
            s.remote.header_key(version, suite)?.key().slice(),
            hex!("edf6d05c83121201b436e16877593c3a")
        );
        Ok(())
    }

    /// Protects `payload` behind `header` with `keys`, as packet number `pn` whose encoding
    /// starts at `pn_offset`.
    fn protect(
        keys: &crypto::Keys,
        header: &[u8],
        payload: &[u8],
        pn: u64,
        pn_offset: usize,
    ) -> Vec<u8> {
        let mut packet = [header, payload, &[0; 16]].concat();
        keys.packet.local.encrypt(pn, &mut packet, header.len());
        keys.header.local.encrypt(pn_offset, &mut packet);
        packet
    }

    /// RFC 9369, appendix A.2: the client's Initial packet.
    #[test]
    fn client_initial_v2() {
        let dcid = ConnectionId::new(&hex!("8394c8f03e515708"));
        let secrets = Secrets::initial(QuicVersion::V2, &dcid, Side::Client).unwrap();
        let keys = secrets.keys().unwrap().as_crypto().unwrap();

        let mut payload = hex!(
            "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69"
            "484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a"
            "00080006001d0017001800100007000504616c706e000500050100000000003300260024001d0020"
            "9370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
            "0d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffff"
            "ffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806"
            "048000ffff"
        )
        .to_vec();
        payload.resize(1162, 0); // PADDING frames
        let header = hex!("d36b3343cf088394c8f03e5157080000449e00000002");

        let protected = protect(&keys, &header, &payload, 2, 18);
        let expected = hex!(
            "d76b3343cf088394c8f03e5157080000449ea0c95e82ffe67b6abcdb4298b485dd04de806071bf03"
            "dceebfa162e75d6c96058bdbfb127cdfcbf903388e99ad049f9a3dd4425ae4d0992cfff18ecf0fdb"
            "5a842d09747052f17ac2053d21f57c5d250f2c4f0e0202b70785b7946e992e58a59ac52dea6774d4"
            "f03b55545243cf1a12834e3f249a78d395e0d18f4d766004f1a2674802a747eaa901c3f10cda5500"
            "cb9122faa9f1df66c392079a1b40f0de1c6054196a11cbea40afb6ef5253cd6818f6625efce3b6de"
            "f6ba7e4b37a40f7732e093daa7d52190935b8da58976ff3312ae50b187c1433c0f028edcc4c2838b"
            "6a9bfc226ca4b4530e7a4ccee1bfa2a3d396ae5a3fb512384b2fdd851f784a65e03f2c4fbe11a53c"
            "7777c023462239dd6f7521a3f6c7d5dd3ec9b3f233773d4b46d23cc375eb198c63301c21801f6520"
            "bcfb7966fc49b393f0061d974a2706df8c4a9449f11d7f3d2dcbb90c6b877045636e7c0c0fe4eb0f"
            "697545460c806910d2c355f1d253bc9d2452aaa549e27a1fac7cf4ed77f322e8fa894b6a83810a34"
            "b361901751a6f5eb65a0326e07de7c1216ccce2d0193f958bb3850a833f7ae432b65bc5a53975c15"
            "5aa4bcb4f7b2c4e54df16efaf6ddea94e2c50b4cd1dfe06017e0e9d02900cffe1935e0491d77ffb4"
            "fdf85290fdd893d577b1131a610ef6a5c32b2ee0293617a37cbb08b847741c3b8017c25ca9052ca1"
            "079d8b78aebd47876d330a30f6a8c6d61dd1ab5589329de714d19d61370f8149748c72f132f0fc99"
            "f34d766c6938597040d8f9e2bb522ff99c63a344d6a2ae8aa8e51b7b90a4a806105fcbca31506c44"
            "6151adfeceb51b91abfe43960977c87471cf9ad4074d30e10d6a7f03c63bd5d4317f68ff325ba3bd"
            "80bf4dc8b52a0ba031758022eb025cdd770b44d6d6cf0670f4e990b22347a7db848265e3e5eb72df"
            "e8299ad7481a408322cac55786e52f633b2fb6b614eaed18d703dd84045a274ae8bfa73379661388"
            "d6991fe39b0d93debb41700b41f90a15c4d526250235ddcd6776fc77bc97e7a417ebcb31600d01e5"
            "7f32162a8560cacc7e27a096d37a1a86952ec71bd89a3e9a30a2a26162984d7740f81193e8238e61"
            "f6b5b984d4d3dfa033c1bb7e4f0037febf406d91c0dccf32acf423cfa1e7071010d3f270121b493c"
            "e85054ef58bada42310138fe081adb04e2bd901f2f13458b3d6758158197107c14ebb193230cd115"
            "7380aa79cae1374a7c1e5bbcb80ee23e06ebfde206bfb0fcbc0edc4ebec309661bdd908d532eb0c6"
            "adc38b7ca7331dce8dfce39ab71e7c32d318d136b6100671a1ae6a6600e3899f31f0eed19e3417d1"
            "34b90c9058f8632c798d4490da4987307cba922d61c39805d072b589bd52fdf1e86215c2d54e6670"
            "e07383a27bbffb5addf47d66aa85a0c6f9f32e59d85a44dd5d3b22dc2be80919b490437ae4f36a0a"
            "e55edf1d0b5cb4e9a3ecabee93dfc6e38d209d0fa6536d27a5d6fbb17641cde27525d61093f1b280"
            "72d111b2b4ae5f89d5974ee12e5cf7d5da4d6a31123041f33e61407e76cffcdcfd7e19ba58cf4b53"
            "6f4c4938ae79324dc402894b44faf8afbab35282ab659d13c93f70412e85cb199a37ddec60054547"
            "3cfb5a05e08d0b209973b2172b4d21fb69745a262ccde96ba18b2faa745b6fe189cf772a9f84cbfc"
        );
        assert_eq!(protected, expected);
    }

    /// RFC 9369, appendix A.3: the server's Initial packet.
    #[test]
    fn server_initial_v2() {
        let dcid = ConnectionId::new(&hex!("8394c8f03e515708"));
        let secrets = Secrets::initial(QuicVersion::V2, &dcid, Side::Server).unwrap();
        let keys = secrets.keys().unwrap().as_crypto().unwrap();

        let payload = hex!(
            "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566d"
            "c5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d10"
            "81287c834d5311bcf32bb9da1a002b00020304"
        );
        let header = hex!("d16b3343cf0008f067a5502a4262b50040750001");

        let protected = protect(&keys, &header, &payload, 1, 18);
        let expected = hex!(
            "dc6b3343cf0008f067a5502a4262b5004075d92faaf16f05d8a4398c47089698baeea26b91eb761d"
            "9b89237bbf87263017915358230035f7fd3945d88965cf17f9af6e16886c61bfc703106fbaf3cb4c"
            "fa52382dd16a393e42757507698075b2c984c707f0a0812d8cd5a6881eaf21ceda98f4bd23f6fe1a"
            "3e2c43edd9ce7ca84bed8521e2e140"
        );
        assert_eq!(protected, expected);
    }

    /// RFC 9369, appendix A.4: a Retry packet in response to the client's Initial.
    #[test]
    fn retry_v2() {
        let orig_dst_cid = ConnectionId::new(&hex!("8394c8f03e515708"));
        let packet =
            hex!("cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6");
        let (header, payload) = packet.split_at(packet.len() - 16 - 5);
        assert!(crate::retry::is_valid_retry(
            &QuicVersion::V2,
            &orig_dst_cid,
            header,
            payload
        ));
        assert!(!crate::retry::is_valid_retry(
            &QuicVersion::V1,
            &orig_dst_cid,
            header,
            payload
        ));

        let (body, tag) = packet.split_at(packet.len() - 16);
        assert_eq!(
            crate::retry::retry_tag(&QuicVersion::V2, &orig_dst_cid, body),
            tag
        );
    }

    /// RFC 9369, appendix A.5: a short header packet with ChaCha20-Poly1305, and the secret after
    /// a key update.
    #[test]
    fn short_packet_v2() {
        const PN: u64 = 654360564;
        let version = QuicVersion::V2;
        let suite = CipherSuite::chacha20_poly1305_sha256();
        let mut secret = Secret::from(&hex!(
            "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
        ));

        let packet_key = secret.packet_key(version, suite).unwrap();
        assert_eq!(
            packet_key.key().slice(),
            hex!("3bfcddd72bcf02541d7fa0dd1f5f9eeea817e09a6963a0e6c7df0f9a1bab90f2")
        );
        assert_eq!(packet_key.iv().slice(), hex!("a6b5bc6ab7dafce30ffff5dd"));
        let header_key = secret.header_key(version, suite).unwrap();
        assert_eq!(
            header_key.key().slice(),
            hex!("d659760d2ba434a226fd37b35c69e2da8211d10c4f12538787d65645d5d1b8e2")
        );

        let mut packet = hex!("4200bff401").to_vec();
        packet.extend_from_slice(&[0; 16]);
        packet_key.encrypt(PN, &mut packet, 4);
        header_key.as_crypto().unwrap().encrypt(1, &mut packet);
        assert_eq!(packet, hex!("5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba"));

        secret.update(version, suite).unwrap();
        assert_eq!(
            secret.slice(),
            hex!("c69374c49e3d2a9466fa689e49d476db5d0dfbc87d32ceeaa6343fd0ae4c7d88")
        );
    }
}

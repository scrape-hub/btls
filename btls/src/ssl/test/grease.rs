use std::collections::HashSet;

use super::client_hello::{
    client_ctx, client_hellos, grease_values, is_grease, single_client_hello,
};
use crate::ssl::test::server::Server;

#[test]
fn grease_sigalgs_first_entry() {
    const CONNECTIONS: usize = 8;

    let mut server = Server::builder();
    server.expected_connections_count(CONNECTIONS + 1);
    let server = server.build();

    let plain = single_client_hello(&server, &client_ctx(|_| {}));
    let plain_sigalgs = plain.signature_algorithms();
    assert!(grease_values(&plain_sigalgs).is_empty());

    let ctx = client_ctx(|ctx| ctx.set_grease_sigalgs_enabled(true));
    let mut seen = HashSet::new();
    for _ in 0..CONNECTIONS {
        let hello = single_client_hello(&server, &ctx);
        let sigalgs = hello.signature_algorithms();

        // One GREASE value in front, the configured list unchanged behind it.
        assert!(is_grease(sigalgs[0]), "{:04x?}", sigalgs);
        assert_eq!(sigalgs[1..], plain_sigalgs[..]);

        // The flag does not depend on `set_grease_enabled`, which stays off here.
        assert!(grease_values(&hello.cipher_suites).is_empty());
        assert!(grease_values(&hello.extension_types()).is_empty());

        seen.insert(sigalgs[0]);
    }

    // The value comes from the per-connection GREASE seed, not a constant.
    assert!(
        seen.len() > 1,
        "same GREASE value {seen:04x?} on every connection"
    );
}

#[test]
fn grease_sigalgs_disabled_by_default() {
    let server = Server::builder().build();

    let ctx = client_ctx(|ctx| ctx.set_grease_enabled(true));
    let hello = single_client_hello(&server, &ctx);

    assert_eq!(grease_values(&hello.cipher_suites).len(), 1);
    assert!(grease_values(&hello.signature_algorithms()).is_empty());
}

#[test]
fn grease_sigalgs_consistent_after_hello_retry_request() {
    // The client predicts an X25519 key share, the server only accepts P-256, which forces a
    // HelloRetryRequest and a second ClientHello.
    let mut server = Server::builder();
    server.ctx().set_curves_list("P-256").unwrap();
    let server = server.build();

    let ctx = client_ctx(|ctx| {
        ctx.set_curves_list("X25519:P-256").unwrap();
        ctx.set_grease_enabled(true);
        ctx.set_grease_sigalgs_enabled(true);
    });
    let hellos = client_hellos(&server, &ctx, |_| {});
    assert_eq!(hellos.len(), 2, "expected a HelloRetryRequest");

    for hello in &hellos {
        let sigalgs = hello.signature_algorithms();
        assert!(is_grease(sigalgs[0]), "{:04x?}", sigalgs);
        assert_eq!(grease_values(&sigalgs).len(), 1);
    }

    // All GREASE values of a connection come from one seed, so the second ClientHello repeats
    // them, including the one in signature_algorithms.
    let [first, second] = &hellos[..] else {
        unreachable!()
    };
    assert_eq!(
        first.signature_algorithms()[0],
        second.signature_algorithms()[0]
    );
    assert_eq!(
        grease_values(&first.cipher_suites),
        grease_values(&second.cipher_suites)
    );
    assert_eq!(
        grease_values(&first.supported_groups()),
        grease_values(&second.supported_groups())
    );
    assert_eq!(
        grease_values(&first.supported_versions()),
        grease_values(&second.supported_versions())
    );
    assert_eq!(
        grease_values(&first.extension_types()),
        grease_values(&second.extension_types())
    );
    assert_eq!(grease_values(&first.extension_types()).len(), 2);
}

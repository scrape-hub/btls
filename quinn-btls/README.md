# quinn-btls

A crypto provider for [quinn](https://github.com/quinn-rs/quinn) based on [BoringSSL](https://github.com/google/boringssl).

## Accolades

A hard fork of [quinn-boring](https://github.com/quinn-rs/quinn-boring).

## Building

This crate requires the [scrape-hub/quinn](https://github.com/scrape-hub/quinn) fork of
`quinn-proto` (its `poll_handshake`/`set_version` additions), not the crates.io release declared
in `Cargo.toml`. Build it as part of this workspace, whose root `Cargo.toml` applies that fork via
`[patch.crates-io]`; building this crate on its own, without that patch, fails to compile.
# Pinned versions

The pins live in `env.sh`; `setup.sh` checks out exactly these.

| Component | Source | Pin |
|---|---|---|
| Tranquil PDS | https://tangled.org/tranquil.farm/tranquil-pds (upstream; the GitHub mirror Bogay/tranquil-pds has no tags) | tag `v0.7.1` = `4e5ded7de520e4cc38ab54e70abb60ecb5f86d60` |
| indigo relay (`cmd/relay`) | https://github.com/bluesky-social/indigo | `51095abf6e9597f041bd510d02ff6a20376f581e` (main, 2026-10-27) |
| PLC directory (`packages/server`) | https://github.com/did-method-plc/did-method-plc (moved from bluesky-social) | `29f1a70ee9f6f80a25946cac103b2f745e371334` (main, 2026-10-27) |
| pnpm (PLC build only) | npm `pnpm` | `11.11.0` (required by PLC's `devEngines`) |
| Rust toolchain | rustup | `1.96.0` (from Tranquil's `rust-toolchain.toml`) |
| Postgres (PLC only) | Ubuntu 24.04 apt `postgresql-16` | 16.x |
| Go / Node | system | Go 1.24.7, Node 22.22 |

Smoke-test npm deps (`package.json`): `@atproto/api` 0.29.6, `@atproto/sync` 0.4.20,
`@atproto/identity` 0.5.20, `tsx` 4.23.15, `typescript` 5.9.3.

Local patches applied on top of the pins by `setup.sh` (see README "Quirks"):
`patches/indigo-relay-localhost-hostcheck.patch`, `patches/tranquil-localhost-http-endpoint.patch`.

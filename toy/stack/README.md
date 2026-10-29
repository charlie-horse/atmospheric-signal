# toy/stack: local ATProto stack

Runs a PLC directory, a Tranquil PDS and an indigo relay as native processes (no Docker).

| Service | Endpoint | Notes |
|---|---|---|
| PLC directory | `http://localhost:2582` | did-method-plc server, backed by Postgres on `127.0.0.1:5442` |
| Tranquil PDS | `http://localhost:3000` | v0.7.1 with the embedded `tranquil-store` (no Postgres) |
| Relay | `ws://localhost:2470` | indigo `cmd/relay` with SQLite. The admin API is at `http://localhost:2470/admin` (user `admin`, password in `data/secrets.env`) |

Pinned revisions are listed in `VERSIONS.md` and set in `env.sh`.

## Run

```sh
cd toy/stack
./setup.sh            # one time: apt deps, clones, patches, builds (the Tranquil release build takes ~9 min on 4 cores)
./up.sh               # start everything, wait for health, register the PDS with the relay
npx tsx smoke.ts      # 2 accounts + 1 is.neuros.atsignal.message record, seen on the relay firehose
./down.sh             # stop (data kept)
./reset.sh            # stop + wipe data/ (accounts, PLC ops, relay state, secrets, logs)
```

All four scripts are idempotent. Logs go to `data/logs/{postgres,plc,tranquil,relay}.log` and pid files to `data/run/`. Build output goes to `vendor/` (gitignored). Build logs are in `vendor/logs/`.

## Account recipe (copy this)

```http
POST http://localhost:3000/xrpc/com.atproto.server.createAccount
{"handle":"alice123.test","email":"alice123@atsig.test","password":"Atsig-alice123-Pw1"}
```

- **Handle:** `<local>.test`. `<local>` is 3–18 characters of `[a-z0-9-]` and can't start or end with `-`. The handle domain comes from `PDS_USER_HANDLE_DOMAINS=test`. `.localhost` is a reserved TLD, so `x.localhost` handles are rejected. If you send a bare `alice123`, Tranquil appends `.test` itself.
- **Email: required.** Without it you get `MissingEmail`, because the verification channel defaults to email. Any syntactically valid address works. No mail is ever sent (the PDS logs "Channel not configured: Email"), and nothing needs verifying: `DISABLE_ACCOUNT_VERIFICATION_GATE=true` allows record writes right away.
- **Password:** at least 8 characters, with a lowercase letter, an uppercase letter and a digit, and not a common password. `pw-alice` is rejected.
- No invite code is needed.
- You get back a `did:plc:...`. Its DID doc lists `#atproto_pds` = `http://localhost:3000`, after patch 2 below.
- `createRecord` for `is.neuros.atsignal.message` works with no `validate` flag and returns `validationStatus: "unknown"`. Bytes fields (`Uint8Array` through `@atproto/api`, i.e. `{"$bytes": ...}` in JSON) round-trip through `getRecord` and the firehose.

## Quirks and workarounds

1. **Relay patch** (`patches/indigo-relay-localhost-hostcheck.patch`). The relay's `CheckHost` uses an SSRF-safe transport that refuses `127.0.0.1`, so even an admin `requestCrawl` of `http://localhost:3000` failed with "not a public IP address". The patch skips the SSRF transport only for `localhost:<port>` hosts, which can only be added through the admin API.
2. **Tranquil patch** (`patches/tranquil-localhost-http-endpoint.patch`). Upstream always writes `https://<hostname>` into PLC genesis ops and DID docs. With `https://localhost:3000`, `AtpAgent` switches to that URL after `createAccount`/`login` and every call fails with `fetch failed`, and `resolveDid().pdsUrl` would be unusable. The patch adds `ServerConfig::pds_endpoint()`, which returns `http://` for a `localhost:<port>` hostname, and uses it at the 11 DID-doc/PLC call sites. The relay ignores the scheme when it compares hosts.
3. **`@atproto/identity` ≥ 0.5 blocks local URLs.** `IdResolver` defaults to an SSRF-protected fetch that rejects `http:` and loopback addresses ("Forbidden protocol"). For the local PLC, pass a plain fetch: `new IdResolver({ plcUrl: 'http://localhost:2582', fetch: globalThis.fetch })`. This also applies to `@atproto/sync`'s `Firehose`, which takes `idResolver`. Without it, every commit fails with "error in parsing and authenticating firehose event".
4. Tranquil requires `DATABASE_URL` even with `REPO_BACKEND=tranquil-store`, although it never connects. `up.sh` passes a dummy value.
5. Tranquil's `CRAWLERS=http://localhost:2470` produces harmless `403` warnings, because the relay runs with `RELAY_DISABLE_REQUEST_CRAWL=true` and is subscribed through the admin API instead. The relay also logs "dropping sync event with old rev" at account creation, which is harmless too.
6. The service DID in `describeServer` is `did:web:localhost:3000`.
7. Postgres runs as the `postgres` user from `data/pg` on port 5442, so it doesn't collide with a system cluster. Only PLC uses it.
8. PLC's `devEngines` hard-requires pnpm 11.11.0. `setup.sh` installs it into `vendor/tools`.

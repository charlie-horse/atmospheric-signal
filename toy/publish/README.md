# toy/publish

Publishes the `is.neuros.atsignal.*` lexicons under the DID `did:web:atsignal.neuros.is` as a static site.

## What is served (GitHub Pages, branch `gh-pages`, custom domain `atsignal.neuros.is`)

| Path | Content |
|---|---|
| `/.well-known/did.json` | DID document: `#atproto` Multikey (secp256k1) and `#atproto_pds` → `https://atsignal.neuros.is` |
| `/.well-known/atproto-did` | The DID, which makes `atsignal.neuros.is` a valid handle |
| `/xrpc/com.atproto.sync.getRecord`, `getRepo` | The full signed repo as a CAR. One `com.atproto.lexicon.schema` record per lexicon (rkey = NSID). A full-repo CAR proves any record, so query strings are ignored. |
| `/xrpc/com.atproto.sync.getLatestCommit`, `com.atproto.repo.describeRepo`, `com.atproto.repo.listRecords` | Static JSON |

DNS (Cloudflare): `CNAME atsignal.neuros.is → charlie-horse.github.io` (unproxied) and `TXT _lexicon.atsignal.neuros.is = "did=did:web:atsignal.neuros.is"`.

## Rebuild and republish

```sh
npm install
npx tsx build.ts                                      # writes ./site (gitignored)
npx tsx serve.ts 8787 &                               # local static server that behaves like GitHub Pages
npx tsx verify.ts http://127.0.0.1:8787 --skip-dns    # must PASS
```

Then replace the contents of the `gh-pages` branch with `site/`, dotfiles included, from a separate clone. Don't use the shared working tree. Check the live site with `npx tsx verify.ts https://atsignal.neuros.is`.

## The key is ephemeral by design

`build.ts` generates a new secp256k1 key on every run and never writes the private key anywhere. Every rebuild re-signs the repo and rewrites `did.json` to match, so there is no secret to keep. The DID and the record contents stay the same, and `did:web` has no history to update. The only cost is that a resolver which cached the old DID document may reject the new commit until it refreshes.

## Known limitation

GitHub Pages serves the extensionless `getRecord` file as `application/octet-stream`. `@atproto/lexicon-resolver` requires `application/vnd.ipld.car` and rejects the response. The proof itself is valid: `verify.ts` checks it directly, and it also retries the resolver with the content type corrected. The resolver works unmodified only if a host can set that header, for example a proxied Cloudflare zone with a response-header Transform Rule.

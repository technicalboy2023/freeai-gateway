# Wave B — OAuth Providers (28) — Design Doc

**Date:** 2026-11-16
**Status:** DRAFT — needs human approval before any build (HARD GATE)
**Research source:** OmniRoute `release/v3.8.54` (`src/lib/oauth/**`) — recon completed 2026-11-16
**Predecessor:** Phase A (API-key gateway) + Wave D (admin console), both landed on `main`
**Chosen approach:** Approach 1 — generic OAuth core + per-provider adapter modules (OmniRoute-style)

---

## 1. Goal

Let the operator sign in to any of the 28 supported OAuth providers **from the admin
console** (`/admin`), store the resulting tokens securely, auto-refresh them, and use
them transparently when forwarding chat traffic — all on the Cloudflare Workers free
tier (₹0), with zero new non-free services.

The user approved: **all 28 providers**, ported in the order already outlined in
`plans/freeai-gateway-v2-admin-console.md` (waves B1→B4).

## 2. Research findings (what we are porting)

OmniRoute's OAuth layer decomposes cleanly:

- **Provider module interface** — every provider is one module:
  `{ config, flowType, buildAuthUrl?, exchangeToken?, requestDeviceCode?, pollToken?,
     postExchange?, importToken?, mapTokens }`
- **flowType values** seen in the registry:
  - `authorization_code_pkce` (claude, codex, cursor, …)
  - `device_code` (github-style: requestDeviceCode → user confirms in browser → pollToken,
    `authorization_pending` / `slow_down` keep polling, `expired_token` / `access_denied` end)
  - `import_token` (paste an existing token; some also set `supportsBrowserPkce`)
  - special: `zed-hosted` returns an RSA-private-key verifier instead of PKCE.
- **Persistence**: connection rows holding tokens + `expiresAt` + non-secret
  `providerSpecificData`; re-auth updates the same row.
- **Paste-blob codec** (`credentialBlob.ts`): base64url blob
  (`omniroute-cred-v1.<payload>`) carrying a raw token response — used when the
  provider's loopback redirect is unreachable from the server.
- **Orchestrator** (`providers.ts`): `generateAuthData` (PKCE + state, returns
  `{supported:false, error}` for disabled flows), `exchangeTokens`, `requestDeviceCode`,
  `pollForToken`, `finalizeTokens`.

### Workers.dev reality check (drives the flow-mode design)

| Provider redirect style | On workers.dev | Mode |
|---|---|---|
| Device flow (worker polls) | ✅ works natively | **device** |
| Fixed provider-hosted callback (claude → `console.anthropic.com/oauth/code/callback`) | ✅ provider shows a code on screen | **paste-code** |
| Our own registered callback (e.g. GitHub OAuth app → `<worker>.workers.dev`) | ✅ after the user registers the URL | **auto-callback** |
| Loopback-only embedded clients (antigravity/agy → `127.0.0.1:<port>`) | ❌ loopback unreachable | **paste-token / paste-blob** |

So one flow engine + four **completion modes**; the mode is a property of each provider
adapter, surfaced in the UI.

## 3. Constraints

- **Free tier only**: Workers + D1. No cron → **refresh-on-use** (before forward), never
  background refresh. No KV dependency for tokens (KV free = 1k writes/day, too tight);
  **D1** (100k writes/day) — this supersedes the old plan note "KV + AES-GCM".
- **Secrets policy** (unchanged from Phase A): tokens live ONLY in D1 (encrypted) or
  Cloudflare secrets — never in code, logs, or API responses.
- **Admin auth**: all new endpoints behind the existing `admin_session` cookie
  (`requireAdmin`).
- **Web-standard APIs only** (Workers): `fetch`, `crypto.subtle`, `crypto.getRandomValues`,
  `AbortSignal.timeout`. No `node:crypto` — OmniRoute's node usage is ported.

## 4. Architecture

```
src/oauth/
  types.ts        OAuthProvider interface (ported, web-standard)
  pkce.ts         code_verifier/challenge (S256) + state via Web Crypto
  crypto.ts       AES-GCM encrypt/decrypt (key = OAUTH_ENCRYPTION_KEY secret)
  store.ts        D1 oauth_tokens / oauth_pending CRUD
  engine.ts       start/complete/poll/status/disconnect dispatcher (per mode)
  refresh.ts      refresh-on-use: ensureFreshToken(env, provider)
  blob.ts         paste-blob codec (port of credentialBlob.ts, base64url)
  providers/      28 adapter files, one per provider
src/index.ts      new /admin/api/oauth/* + /admin/oauth/:provider/callback routes
src/forward.ts    oauth providers pull their Bearer token from the store, not env
src/providers.ts  ProviderConfig gains optional `oauth?: true` + secret-free shape
migrations/0003_oauth_tokens.sql   two tables below
public/admin/*    Connect / device-code / paste UI in provider cards
```

### D1 schema (migration 0003)

```sql
CREATE TABLE oauth_tokens (
  provider        TEXT PRIMARY KEY,
  access_token    BLOB NOT NULL,        -- AES-GCM ciphertext (12-byte IV prefix)
  refresh_token   BLOB,                 -- encrypted; NULL when provider omits it
  expires_at      INTEGER,              -- epoch ms; NULL = provider never expires
  account_label   TEXT,                 -- email / display name (non-secret)
  meta            TEXT,                 -- providerSpecificData JSON (non-secret only)
  auth_kind       TEXT NOT NULL,        -- 'oauth' | 'paste'
  connected_at    INTEGER NOT NULL,
  last_refresh_at INTEGER,
  last_error      TEXT
);
CREATE TABLE oauth_pending (
  provider      TEXT PRIMARY KEY,       -- one flow at a time per provider
  mode          TEXT NOT NULL,          -- 'pkce' | 'device'
  state         TEXT,
  code_verifier TEXT,
  device_code   TEXT,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL
);
```

One connection **per provider** (single-operator gateway — simpler than OmniRoute's
multi-account rows; re-login replaces in place). Non-secret metadata (`meta`) is
whitelist-mapped by each adapter's `mapTokens` — tokens never enter it.

### Crypto

- `OAUTH_ENCRYPTION_KEY` secret: 32 random bytes, base64url-encoded
  (`openssl rand -base64 32`). Worker imports as `crypto.subtle` AES-GCM key.
- Per-encryption random 12-byte IV, stored prefixed to the ciphertext BLOB.
- Missing/unset secret → OAuth endpoints answer honest `503 {error: "set
  OAUTH_ENCRYPTION_KEY secret first"}` (matches Wave D strict-config ruling).
- Decrypt failure → row treated as corrupt → `last_error`, endpoint reports disconnect
  required. Never silently fall back to plaintext.

### Forward integration (the part that makes tokens useful)

- `ProviderConfig` gains `oauth?: true` (and `keySecret` becomes optional for those).
- `forwardToProvider`: if `resolved.oauth` → `const token = await ensureFreshToken(env, prefix)`
  and use `authorization: Bearer <token>` (or provider-mandated header via adapter hook
  `authHeaders(token)`). No env secret lookup. Missing/disabled/expired-refused →
  `MissingTokenError` → same 400/skip-in-chain behavior as `MissingKeyError`.
- API-key providers are untouched (existing 130 tests must stay green).

### Refresh engine (`refresh.ts`)

- `ensureFreshToken`: decrypt; if `expires_at` set and `< now + 5min` skew and
  refresh_token exists → refresh **before** forwarding:
  standard `grant_type=refresh_token` POST to the adapter's token URL, adapter hook
  `refreshToken?` for non-standard providers; `401 invalid_grant` → store `last_error`,
  throw `MissingTokenError` (chain skips, direct call 400 names the provider).
- Upsert the rotated tokens (some providers rotate refresh tokens — always save
  whatever comes back). Occasional races between two overlapping refreshes are
  acceptable (last write wins; D1 conditional update guard optional later).
- Free-tier math: refreshes are per-provider occasional events; writes/day nowhere near
  100k.

## 5. Flow designs (admin console UX)

All endpoints are admin-cookie protected; all responses no-store; tokens never echoed.

1. **`POST /admin/api/oauth/:provider/start`**
   - `device` adapter → requests device code upstream, stores pending row, returns
     `{user_code, verification_uri, expires_in, interval}` — console shows code + link,
     auto-polls.
   - `pkce` adapter → generates verifier + state, stores pending, returns
     `{authUrl, mode: "paste-code" | "auto-callback"}`.
   - `paste` adapter → returns `{mode: "paste"}` + instructions string from adapter.
2. **`POST /admin/api/oauth/:provider/complete`**
   - paste-code: `{code}` → exchange with stored verifier → persist.
   - auto-callback redirect lands on **`GET /admin/oauth/:provider/callback?code&state`**
     (worker route) which completes server-side and redirects to `/admin?oauth=<provider>`—
     the same handler is reused when the user manually pastes the code.
   - paste: `{token}` raw token **or** `{blob}` (`omniroute-cred-v1.…`) → decode → persist
     (adapter `importToken` validates shape).
   - device: `{}` → engine polls upstream once with the stored device code; returns
     `{status: "pending" | "connected" | "error", ...}` — console JS keeps polling every
     `interval` seconds until connected/expired.
3. **`GET /admin/api/oauth/:provider/status`** → `{connected, expiresAt, accountLabel,
   lastError}` (never token material).
4. **`DELETE /admin/api/oauth/:provider`** → delete row (disconnect).

Console UI: provider cards (existing 8 + OAuth sections) show a Connect control; flow
type decides which form appears (device code display / code-paste box / token-paste box).
Status badge: connected (expiry date) / disconnected / error.

## 6. Provider target list + build waves

Ported 1:1 from OmniRoute modules (recon'd interface), rewritten web-standard. Exact
per-module behavior is re-read from OmniRoute source **during each batch's plan tasks**
(small files; no guessing).

| Wave | Providers | Flow mode(s) |
|---|---|---|
| **B0 engine** (shared core, no provider) | types, pkce, crypto, store, engine, refresh, blob, routes, UI shell, migration 0003 | all four modes wired with a fake provider in tests |
| **B1 paste** (7) | trae, agy, devin-desktop, freebuff, kilocode, cline, codebuddy-cn + codebuddy-intl | paste-token (+blob where OmniRoute supports it) |
| **B2 device** (6) | github, ghe-copilot, kimi-coding, muse-code, workbuddy, minimax-code | device (+paste for freebuff) |
| **B3 PKCE** (7) | claude, codex, xai-oauth, grok-cli, cursor, openference, clinepass | paste-code / auto-callback (per provider) |
| **B4 hard** (4) | antigravity, amazon-q*, zed-hosted, gitlab-duo | paste-blob / manual / RSA-verifier / hosted |
| **B5 leftovers** (3–4) | megabrain, renderhour, copilot-m365-web (+ any module found during plan recon) | flow per OmniRoute module |

**Exclusions** (per existing plan line 222): `kiro` (= amazon-q identity, ToS),
`devin-cli`, `qoder`, `zed` (local-only — need OS keychain / local CLI profiles a server
cannot reach). `amazon-q` stays excluded under the same ToS ruling; flag if you want it
included anyway.

Each batch: TDD (RED→GREEN), suite green + `tsc` clean at every commit, one commit per
task, ledger updated (`progress.md`), README updated at the end.

## 7. Security

- Tokens AES-GCM encrypted at rest; IV random per write; key only in CF secret.
- Never in logs, never in API/JSON responses, never in `meta`.
- All endpoints `requireAdmin` + `no-store`; state/verifier single-use (pending row
  deleted on complete), pending rows expire (`expires_at`, e.g. 10 min PKCE / 15 min device).
- Comparisons via timing-safe helper where two secrets/states are compared.
- Paste-blob decode strictly validates prefix/shape (port behavior), rejects oversized
  input (e.g. >16 KB).
- Error tags in logs stay coarse (`oauth-failed:<provider>`), never include token/code.

## 8. Test strategy (vitest, no real network)

- **Unit per adapter**: canned upstream JSON → `requestDeviceCode` / `pollToken` /
  `exchangeToken` / `importToken` / `mapTokens` shape; error branches
  (authorization_pending, slow_down, expired, denied, network 0).
- **crypto.ts**: roundtrip encrypt/decrypt, wrong-key → decrypt failure path, missing
  secret → 503.
- **store.ts**: upsert replaces, expiry math, pending lifecycle (create → consume → gone).
- **engine.ts**: per mode — start/complete/poll status transitions; state single-use.
- **refresh.ts**: near-expiry triggers one refresh (mocked fetch), saves rotated tokens,
  invalid_grant → error + throw.
- **forward.ts**: oauth provider pulls store token as Bearer; API-key providers unchanged.
- **routes**: 401 without cookie (all new endpoints), 503 without encryption key,
  404 unknown provider.
- **DOM tests** (`admin-ui-dom.test.ts` pattern, fresh Window per test): Connect flow
  renders per mode, poll loop wiring, paste input submit, status badge.

## 9. Non-goals

- Multi-account per provider (one connection each).
- Background/cron refresh (free plan) — refresh-on-use only.
- Converting OpenAI↔Anthropic request formats for OAuth providers: forwarding uses each
  provider's native path/format exactly like the existing `auth: "anthropic"` provider
  does today; deeper format conversion stays a Phase C concern if needed.
- Real-account end-to-end tests in CI (live OAuth needs human login — manual smoke only,
  with the user, per provider batch).

## 10. Open questions for approval

1. **amazon-q/kiro**: keep ToS exclusion (default), or include?
2. **copilot-m365-web**: Microsoft business-account flow is the heaviest module — OK to
   push it to last (B5), possibly cut if it drags? (default: include, last)
3. **OAUTH_ENCRYPTION_KEY**: confirm you're fine adding one more wrangler secret at
   deploy time (`openssl rand -base64 32` → `wrangler secret put`).

## 11. Approval

- [ ] Human approves this design doc
- [ ] → then `superpowers:writing-plans` produces the Wave B execution plan
- [ ] → then TDD execution batch by batch

# Wave B — Plan 1: OAuth Engine + Simple Providers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the OAuth layer (connect from admin console → encrypted D1 token store → refresh-on-use → forward hook) and port the 7 recon-verified simple providers (trae, devin-desktop, cline, kilocode, freebuff, codebuddy-cn, codebuddy-intl).

**Architecture:** Generic `src/oauth/` core (types, Web-Crypto AES-GCM, PKCE, paste-blob, D1 store, flow engine, refresh) + one adapter file per provider (`src/oauth/providers/`), OmniRoute `release/v3.8.54` modules ported 1:1 to web-standard APIs. Three flow modes ship: `paste`, `paste-code`, `device`.

**Tech Stack:** Cloudflare Workers (web-standard APIs only), D1, vanilla admin SPA (no build step), vitest.

**Spec:** `docs/superpowers/specs/2026-11-16-waveb-oauth-design.md` (approved). Follow-up plans after this one lands: Plan 2 = standard-OAuth batch (device: github, ghe-copilot, kimi-coding, muse-code, workbuddy, minimax-code; PKCE/paste-code: claude, codex, xai-oauth, grok-cli, cursor, openference, clinepass), Plan 3 = hard batch (antigravity, agy, zed-hosted, gitlab-duo, copilot-m365-web, megabrain, renderhour).

## Global Constraints

- **Web-standard APIs only in `src/`**: `fetch`, `crypto.subtle`, `crypto.getRandomValues`, `atob`/`btoa`, `AbortSignal.timeout`. No `node:crypto`, no `Buffer` in worker code (tests may use Node APIs).
- **Tokens live ONLY in D1, AES-GCM encrypted** (key from `OAUTH_ENCRYPTION_KEY` secret). Tokens never in logs, never echoed in API responses; `meta` never carries token material.
- All `/admin/api/oauth/*` endpoints behind the existing admin cookie gate; responses `no-store`.
- No cron on free plan → **refresh-on-use only** (before forward).
- Existing suite (130 tests / 15 files) green + `npm run typecheck` clean at **every** commit.
- TDD every task: failing test first (RED), then implement (GREEN), then commit. One commit per task.
- Machine: Windows/PowerShell; stale shells need `$env:Path = 'C:\Program Files\Git\cmd;' + $env:Path` for git.

## Review Focus

1. **Expired pending flow reused** (PKCE state / device code older than its TTL): `getPending` must return `null` and complete/poll must answer 410-style OAuthError — pinned in Task 3 (store expiry) and Task 4 (engine complete/poll).
2. **Unknown provider prefix** on any oauth route: clean 404 JSON, never an unhandled throw — pinned in Task 6.
3. **Missing `OAUTH_ENCRYPTION_KEY` secret**: every write path answers honest 503 "set OAUTH_ENCRYPTION_KEY secret first", never writes plaintext — pinned in Task 1 (crypto) and Task 6 (routes).
4. **Garbage paste input** (empty / <16 chars / wrong shape): adapter validation surfaces as 400 with the adapter's message, no row written — pinned in Task 7 (devin validation) and Task 8 (cline decode failure → fallback exchange).
5. **Device flow terminal states** (`access_denied`, `expired_token`): pending row deleted, poll answers `{status:"error"}`, UI poll loop stops — pinned in Task 4 (engine) and Task 12 (DOM).

---

## File Structure

```
migrations/0003_oauth_tokens.sql   Create — oauth_tokens + oauth_pending tables
src/env.ts                         Modify — add OAUTH_ENCRYPTION_KEY?: string
src/oauth/types.ts                 Create — OAuthAdapter, MappedTokens, PollResult, FlowMode
src/oauth/crypto.ts                Create — importAesKey, encryptToken, decryptToken
src/oauth/pkce.ts                  Create — generatePkce (verifier + S256 challenge + state)
src/oauth/blob.ts                  Create — paste-blob codec (freeai-cred-v1.)
src/oauth/store.ts                 Create — oauth_tokens / oauth_pending CRUD
src/oauth/engine.ts                Create — start/complete/poll/status/disconnect + adapter registry
src/oauth/refresh.ts               Create — ensureFreshToken (refresh-on-use)
src/oauth/providers/registry.ts    Create — OAUTH_ADAPTERS list (grows per task)
src/oauth/providers/trae.ts        Create — paste adapter
src/oauth/providers/devin-desktop.ts Create — paste adapter
src/oauth/providers/cline.ts       Create — paste-code adapter
src/oauth/providers/kilocode.ts    Create — device adapter
src/oauth/providers/freebuff.ts    Create — device adapter
src/oauth/providers/codebuddy.ts   Create — shared device-auth + cn/intl adapters
src/admin/oauth.ts                 Create — route handlers (pattern of src/admin/providers.ts)
src/index.ts                       Modify — /admin/api/oauth/* routes (before the /admin assets catch-all)
src/providers.ts                   Modify — ProviderConfig gains oauth?: boolean, keySecret?: string
src/forward.ts                     Modify — oauth branch + MissingTokenError
public/admin/index.html            Modify — OAuth section in Overview tab
public/admin/app.js                Modify — oauth cards, three connect flows, poll loop
public/admin/app.css               Modify — oauth card styles
README.md                          Modify — OAuth section
```

Shared recon values used verbatim (from OmniRoute `release/v3.8.54`):

- `TRAE_CONFIG`: tokenLifetimeDays **14**, authScheme `Cloud-IDE-JWT`, tokenNote: "Authorize via trae.ai in the popup, or sign in to solo.trae.ai and paste the Cloud-IDE-JWT from the Authorization header (~14-day lifetime)."
- `DEVIN_DESKTOP_CONFIG`: session-token prefix `devin-session-token$` (normalize to exactly one).
- `CLINE_CONFIG`: authorizeUrl `https://api.cline.bot/api/v1/auth/authorize`, tokenExchangeUrl `https://api.cline.bot/api/v1/auth/token`, refreshUrl `https://api.cline.bot/api/v1/auth/refresh`.
- `KILOCODE_CONFIG`: initiateUrl + pollUrlBase `https://api.kilo.ai/api/device-auth/codes`.
- `FREEBUFF_CONFIG`: codeUrl `https://freebuff.com/api/auth/cli/code`, statusUrl `https://freebuff.com/api/auth/cli/status`, loginTimeoutSec 300, pollInterval 5000.
- `CODEBUDDY_CN_CONFIG`: stateUrl `https://copilot.tencent.com/v2/plugin/auth/state`, tokenUrl `https://copilot.tencent.com/v2/plugin/auth/token`, platform `CLI`, domain `copilot.tencent.com`, pollInterval 5000.
- `CODEBUDDY_INTL_CONFIG`: same paths on `https://www.codebuddy.ai`, platform `ide`, domain `www.codebuddy.ai`, pollInterval 5000.

---

### Task 1: Migration 0003 + Env + token crypto

**Files:**
- Create: `migrations/0003_oauth_tokens.sql`
- Modify: `src/env.ts` (add `OAUTH_ENCRYPTION_KEY?: string;` after `ADMIN_PASSWORD`)
- Create: `src/oauth/crypto.ts`
- Test: `test/oauth-crypto.test.ts`

**Interfaces:**
- Produces:
  - `importAesKey(env: Env): Promise<CryptoKey | null>` — decodes `env.OAUTH_ENCRYPTION_KEY` (base64url, 32 decoded bytes) via `crypto.subtle.importKey("raw", …, "AES-GCM", false)`; returns `null` when the secret is missing or not 32 decoded bytes.
  - `encryptToken(key: CryptoKey, plaintext: string): Promise<Uint8Array>` — random 12-byte IV prepended: `iv ‖ ciphertext`.
  - `decryptToken(key: CryptoKey, blob: Uint8Array): Promise<string>` — throws on wrong key/tamper (let the caller decide).

- [ ] **Step 1: Write the failing tests** in `test/oauth-crypto.test.ts`

```ts
const KEY = b64urlOfBytes(new Uint8Array(32).fill(0x41)); // helper builds base64url of 32×0x41
it("roundtrips encrypt/decrypt", async () => {
  const key = await importAesKey({ OAUTH_ENCRYPTION_KEY: KEY } as Env);
  expect(key).not.toBeNull();
  const blob = await encryptToken(key!, "sk-secret-token");
  expect(await decryptToken(key!, blob)).toBe("sk-secret-token");
});
it("produces a fresh IV per call", async () => {
  const key = (await importAesKey({ OAUTH_ENCRYPTION_KEY: KEY } as Env))!;
  const a = await encryptToken(key, "t"); const b = await encryptToken(key, "t");
  expect(Array.from(a.slice(0, 12))).not.toEqual(Array.from(b.slice(0, 12)));
  expect(a.length).toBe(b.length);
});
it("wrong key fails to decrypt (does not throw a plaintext leak)", async () => {
  const k1 = (await importAesKey({ OAUTH_ENCRYPTION_KEY: KEY } as Env))!;
  const blob = await encryptToken(k1, "sk-secret");
  const k2 = (await importAesKey({ OAUTH_ENCRYPTION_KEY: b64urlOfBytes(new Uint8Array(32).fill(0x42)) } as Env))!;
  await expect(decryptToken(k2, blob)).rejects.toThrow();
});
it("missing / wrong-length secret returns null key", async () => {
  expect(await importAesKey({} as Env)).toBeNull();
  expect(await importAesKey({ OAUTH_ENCRYPTION_KEY: b64urlOfBytes(new Uint8Array(16).fill(0x41)) } as Env)).toBeNull();
});
```

- [ ] **Step 2: Run to verify FAIL** — `npm test -- test/oauth-crypto.test.ts` → FAIL (module not found)
- [ ] **Step 3: Implement** `src/oauth/crypto.ts` — Web Crypto only: `crypto.subtle.importKey`, `crypto.getRandomValues(new Uint8Array(12))` IV, `crypto.subtle.encrypt/decrypt({name:"AES-GCM", iv}, …)`. Base64url decode: `atob` after `-`→`+`, `_`→`/`, pad with `=`.
- [ ] **Step 4: Run to verify PASS** — same command → PASS
- [ ] **Step 5: Commit**

```bash
git add migrations/0003_oauth_tokens.sql src/env.ts src/oauth/crypto.ts test/oauth-crypto.test.ts
git commit -m "feat(oauth): migration 0003 + AES-GCM token crypto"
```

Migration 0003 exact content (goes in the same commit):

```sql
CREATE TABLE oauth_tokens (
  provider        TEXT PRIMARY KEY,
  access_token    BLOB NOT NULL,
  refresh_token   BLOB,
  expires_at      INTEGER,
  account_label   TEXT,
  meta            TEXT,
  auth_kind       TEXT NOT NULL DEFAULT 'oauth',
  connected_at    INTEGER NOT NULL,
  last_refresh_at INTEGER,
  last_error      TEXT
);
CREATE TABLE oauth_pending (
  provider      TEXT PRIMARY KEY,
  mode          TEXT NOT NULL,
  state         TEXT,
  code_verifier TEXT,
  device_code   TEXT,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL
);
```

---

### Task 2: PKCE + paste-blob codec

**Files:**
- Create: `src/oauth/pkce.ts`, `src/oauth/blob.ts`
- Test: `test/oauth-pkce.test.ts`, `test/oauth-blob.test.ts`

**Interfaces:**
- Consumes: nothing (leaf modules).
- Produces:
  - `generatePkce(verifierBytes = 32): Promise<{ codeVerifier: string; codeChallenge: string; state: string }>` — verifier/state base64url of `crypto.getRandomValues`; challenge = base64url(SHA-256(verifier)) per RFC 7636.
  - `encodeCredentialBlob(input: { provider: string; tokens: Record<string, unknown> }): string` — `freeai-cred-v1.` + base64url(JSON `{v:1, provider, tokens}`); throws when provider empty or tokens missing.
  - `decodeCredentialBlob(blob: string): { provider: string; tokens: Record<string, unknown> }` — throws on bad prefix / non-base64url body / wrong `v` / missing provider / missing `access_token` / body > 16384 chars.

- [ ] **Step 1: Write failing tests** — RFC 7636 Appendix B vector pins the challenge:

```ts
it("matches the RFC 7636 S256 vector", async () => {
  const { codeChallenge } = await deriveChallengeForTest("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
  expect(codeChallenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
});
it("generates url-safe verifier/state of expected lengths", async () => {
  const p = await generatePkce(32);
  expect(p.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43}$/); // 32 bytes → 43 base64url chars
  expect(p.state.length).toBeGreaterThanOrEqual(16);
  expect(p.codeChallenge).toMatch(/^[A-Za-z0-9_-]+$/);
});
```

Blob tests: roundtrip decode equals input; rejects wrong prefix, wrong `v`, missing `access_token`, empty provider, >16384-char body.

- [ ] **Step 2: Run → FAIL** (`npm test -- test/oauth-pkce.test.ts test/oauth-blob.test.ts`)
- [ ] **Step 3: Implement** — `pkce.ts` uses `crypto.subtle.digest("SHA-256", encoder.encode(verifier))`; export `deriveChallengeForTest(verifier)` as the deterministic seam used by the RFC test. `blob.ts` ports OmniRoute `credentialBlob.ts` shape with prefix `freeai-cred-v1.`, version 1.
- [ ] **Step 4: Run → PASS**
- [ ] **Step 5: Commit** — `git commit -m "feat(oauth): pkce + paste-blob codec (web crypto)"` (include both files + tests)

---

### Task 3: Encrypted D1 token store

**Files:**
- Create: `src/oauth/store.ts`
- Test: `test/oauth-store.test.ts` (hand-rolled D1 stub keyed by SQL shape, same pattern as `stubDb` in `test/admin-ops.test.ts`)

**Interfaces:**
- Consumes: `importAesKey/encryptToken/decryptToken` (Task 1).
- Produces:
  - `type TokenRow = { provider: string; accessToken: string; refreshToken?: string | null; expiresAt?: number | null; accountLabel?: string | null; meta?: Record<string, unknown>; authKind: string; connectedAt: number; lastRefreshAt?: number | null; lastError?: string | null }`
  - `type PendingRow = { provider: string; mode: "pkce" | "device"; state?: string | null; codeVerifier?: string | null; deviceCode?: string | null; createdAt: number; expiresAt: number }`
  - `saveToken(env: Env, t: { provider: string; accessToken: string; refreshToken?: string | null; expiresIn?: number | null; email?: string | null; name?: string | null; meta?: Record<string, unknown>; authKind: string }): Promise<void>` — upsert; `expiresAt = t.expiresIn ? Date.now() + t.expiresIn*1000 : null`; encrypts access+refresh as BLOBs; `meta = t.meta ? JSON.stringify(t.meta) : null`.
  - `getToken(env: Env, provider: string): Promise<TokenRow | null>` — decrypts; decrypt failure → row treated as corrupt: sets `last_error`, returns `null`.
  - `deleteToken(env: Env, provider: string): Promise<void>`
  - `getTokenStatus(env: Env, provider: string): Promise<{ connected: boolean; expiresAt: number | null; accountLabel: string | null; lastError: string | null; authKind: string } | null>`
  - `savePending(env: Env, p: { provider: string; mode: "pkce" | "device"; state?: string | null; codeVerifier?: string | null; deviceCode?: string | null; ttlSec: number }): Promise<void>` (upsert — one flow at a time per provider)
  - `getPending(env: Env, provider: string): Promise<PendingRow | null>` — **returns null when `expiresAt < Date.now()`** (Review Focus #1)
  - `deletePending(env: Env, provider: string): Promise<void>`
  - Every function: no `env.DB` → throw `Error("DB binding not configured")`.

- [ ] **Step 1: Write failing tests** — roundtrip save→getToken returns decrypted values + parsed meta; status shape; delete; pending save→get→expired (ttl 0 / created in past)→null; pending upsert overwrites; no-DB throws.
- [ ] **Step 2: Run → FAIL**
- [ ] **Step 3: Implement** — SQL per migration 0003 columns; BLOB binding takes the `Uint8Array` directly.
- [ ] **Step 4: Run → PASS**
- [ ] **Step 5: Commit** — `git commit -m "feat(oauth): encrypted D1 token store"`

---

### Task 4: Flow engine (paste / paste-code / device)

**Files:**
- Create: `src/oauth/types.ts`, `src/oauth/engine.ts`
- Test: `test/oauth-engine.test.ts`

**Interfaces:**
- Consumes: store (Task 3), pkce/blob (Task 2), crypto (Task 1).
- Produces (`types.ts`):

```ts
export type FlowMode = "paste" | "paste-code" | "device";
export interface DeviceCodeResponse { device_code: string; user_code: string; verification_uri: string; verification_uri_complete?: string; expires_in: number; interval: number }
export interface RawTokens { [k: string]: unknown }
export interface PollResult { ok: boolean; data: RawTokens }
export interface MappedTokens { accessToken: string; refreshToken?: string | null; expiresIn?: number | null; email?: string | null; name?: string | null; meta?: Record<string, unknown> }
export interface OAuthAdapter {
  prefix: string;
  flowMode: FlowMode;
  config: Record<string, unknown>;
  instructions?: string;
  redirectUri?: string;                       // overrides `${origin}/admin` for paste-code
  buildAuthUrl?(config: OAuthAdapter["config"], redirectUri: string, state: string, codeChallenge: string): string;
  exchangeToken?(config: OAuthAdapter["config"], code: string, redirectUri: string, codeVerifier: string, state: string): Promise<RawTokens>;
  requestDeviceCode?(config: OAuthAdapter["config"]): Promise<DeviceCodeResponse>;
  pollToken?(config: OAuthAdapter["config"], deviceCode: string): Promise<PollResult>;
  importToken?(raw: RawTokens): Promise<RawTokens>;
  mapTokens(tokens: RawTokens): MappedTokens;
}
```

- Produces (`engine.ts`):

```ts
export class OAuthError extends Error { constructor(public status: number, message: string) }
export function registerAdapter(a: OAuthAdapter): void          // map.set (tests inject fakes)
export function getAdapter(prefix: string): OAuthAdapter | null
export function listAdapters(): OAuthAdapter[]                  // sorted by prefix
export type StartResult =
  | { mode: "paste"; instructions: string }
  | { mode: "paste-code"; authUrl: string; state: string }
  | { mode: "device"; user_code: string; verification_uri: string; verification_uri_complete: string; expires_in: number; interval: number };
export async function start(env: Env, prefix: string, requestUrl: URL): Promise<StartResult>
export async function complete(env: Env, prefix: string, input: { code?: string; token?: string; blob?: string }): Promise<{ connected: true; accountLabel: string | null }>
export async function poll(env: Env, prefix: string): Promise<{ status: "pending" | "connected" | "error"; error?: string }>
export async function statusOf(env: Env, prefix: string): Promise<{ connected: boolean; expiresAt: number | null; accountLabel: string | null; lastError: string | null; flowMode: FlowMode }>
export async function disconnect(env: Env, prefix: string): Promise<void>
```

Engine behavior (the decisions a task implementer cannot make):
- `start` paste → `{mode:"paste", instructions: a.instructions ?? "Paste the provider token."}`.
- `start` paste-code → requires `buildAuthUrl`+`exchangeToken` else `OAuthError(400, "…does not support paste-code")`; PKCE 32 bytes; pending `{mode:"pkce", state, codeVerifier, ttlSec: 600}`; redirectUri = `a.redirectUri ?? new URL("/admin", requestUrl.origin).toString()`.
- `start` device → requires `requestDeviceCode` else 400; pending `{mode:"device", deviceCode: d.device_code, ttlSec: 900}`.
- `complete` paste: `token` → tokens = `{access_token: token}`; `blob` → `decodeCredentialBlob`; neither → `OAuthError(400, "paste a token or blob")`. Then `finalizeTokens`: `if (a.importToken) tokens = await a.importToken(tokens)`, then `mapTokens` → `saveToken(authKind:"paste")`. Adapter throw → `OAuthError(400, <message>)`, **no row written** (Review Focus #4).
- `complete` paste-code: pending must exist and be mode `pkce` (expired/missing → `OAuthError(410, "login flow expired — start again")`); `exchangeToken(config, code, redirectUri, pending.codeVerifier, pending.state)`; on success save (authKind `"oauth"`) + `deletePending`. Adapter throw → 400, pending kept.
- `poll` device: pending missing/expired → `{status:"error", error:"expired"}` (already handled as 410 for complete; poll is UI-friendly). `pollToken` → ok+access_token → finalize/save (authKind `"oauth"`)/`deletePending` → connected; `error: authorization_pending | slow_down` → `{status:"pending", error}`; any other error → `{status:"error", error}` **and deletePending** (terminal; Review Focus #5). `access_token` missing on ok → error path. authKind: `"paste"` for paste mode, `"oauth"` for paste-code and device.
- `statusOf`/`disconnect` thin over store; unknown adapter → `OAuthError(404, "Unknown OAuth provider: <prefix>")` from all five functions.

- [ ] **Step 1: Write failing tests** with two fake adapters in-test: `pasteFake` (importToken throws on empty; mapTokens fixed), `codeFake` (buildAuthUrl echoes params, exchangeToken returns canned), `deviceFake` (requestDeviceCode/pollToken canned). Pin: start shapes per mode; complete paste writes encrypted row (read back via getToken); complete paste-code happy path + expired-pending 410 + single-use (pending gone); poll pending→connected transition + terminal error deletes pending; unknown prefix 404.
- [ ] **Step 2: Run → FAIL** (`npm test -- test/oauth-engine.test.ts`)
- [ ] **Step 3: Implement** `types.ts` + `engine.ts` (no provider imports in engine).
- [ ] **Step 4: Run → PASS**
- [ ] **Step 5: Commit** — `git commit -m "feat(oauth): flow engine (paste, paste-code, device)"`

---

### Task 5: Refresh-on-use engine

**Files:**
- Create: `src/oauth/refresh.ts`
- Test: `test/oauth-refresh.test.ts`

**Interfaces:**
- Consumes: store (Task 3), engine `getAdapter` (Task 4).
- Produces:
  - `class TokenExpiredError extends Error { constructor(public prefix: string, public detail: string) }`
  - `REFRESH_SKEW_SEC = 300`
  - `ensureFreshToken(env: Env, prefix: string): Promise<string>` — `getToken`; null → `TokenExpiredError(prefix, "not connected")`. If `refreshToken` set AND `expiresAt` non-null AND `expiresAt - Date.now() < 300000` → refresh: adapter `refresh?` hook when defined, else standard form POST to `config.tokenUrl` with `grant_type=refresh_token&client_id=<config.clientId>&refresh_token=<rt>` (`application/x-www-form-urlencoded`); ok JSON → `mapTokens` → `saveToken(authKind:"oauth")`; non-ok/`invalid_grant` → store `last_error` (via `saveToken` re-save of the old row is wrong — use dedicated `markTokenError(env, provider, error)` exported from `refresh.ts`) and `throw TokenExpiredError(prefix, "refresh rejected")`. Fresh-enough token → return as-is. No `refreshToken` and expired → `TokenExpiredError(prefix, "token expired, no refresh grant")`.

- [ ] **Step 1: Write failing tests** (fake adapter + fetch mock via `vi.stubGlobal("fetch", …)`): valid token → no fetch call; near-expiry → exactly one POST, form body has grant/client_id/refresh_token, rotated tokens persisted (getToken shows new token + `lastRefreshAt`); `invalid_grant` → TokenExpiredError + `lastError` recorded; missing row → TokenExpiredError "not connected".
- [ ] **Step 2: Run → FAIL**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run → PASS**
- [ ] **Step 5: Commit** — `git commit -m "feat(oauth): refresh-on-use engine"`

Note (ledger TODO, not this plan): cline + codebuddy publish non-standard refresh URLs whose exact request shapes are unrecon'd — Plan 2 recones them; until then those two providers rely on re-connect after expiry.

---

### Task 6: Admin OAuth API routes

**Files:**
- Create: `src/admin/oauth.ts` (handler pattern of `src/admin/providers.ts`: try/catch, `jsonResponse`, OAuthError → `{error:{message}}` with its status)
- Modify: `src/index.ts` — import handlers; route block placed **before** the `/admin` assets catch-all:

```ts
if (pathname.startsWith("/admin/api/oauth")) {
  const denied = await adminGate(request, env);
  if (denied) return denied;
  if (pathname === "/admin/api/oauth" && request.method === "GET") return handleOauthList(env);
  const m = pathname.match(/^\/admin\/api\/oauth\/([a-z0-9_-]+)(\/(start|complete|poll|status))?$/);
  if (m) {
    const [, prefix, , action] = m;
    if (request.method === "POST" && action === "start") return handleOauthStart(request, env, prefix);
    if (request.method === "POST" && action === "complete") return handleOauthComplete(request, env, prefix);
    if (request.method === "GET" && action === "poll") return handleOauthPoll(env, prefix);
    if (request.method === "GET" && action === "status") return handleOauthStatus(env, prefix);
    if (request.method === "DELETE" && !action) return handleOauthDisconnect(env, prefix);
  }
  return jsonResponse({ error: { message: `No admin route: ${request.method} ${pathname}` } }, 404);
}
```

**Interfaces:**
- Consumes: engine functions (Task 4), `listAdapters`.
- Produces (handlers; JSON shapes the UI in Task 12 consumes):
  - `handleOauthList(env) → { providers: [{ prefix, flowMode, connected, expiresAt, accountLabel, lastError, instructions? }] }`
  - `handleOauthStart(request, env, prefix)` → StartResult JSON (paste-code start reads request URL origin for redirectUri)
  - `handleOauthComplete(request, env, prefix)` → reads `{code?, token?, blob?}` from JSON body
  - `handleOauthPoll(env, prefix)` → poll result
  - `handleOauthStatus(env, prefix)` → statusOf or 404 for unknown provider
  - `handleOauthDisconnect(env, prefix)` → `{ disconnected: prefix }`

- [ ] **Step 1: Write failing tests** in `test/admin-oauth.test.ts` (gateway.fetch + stubDb + login cookie, pattern of `test/admin-oauth` peers like admin-providers.test.ts): all six endpoints 401 without cookie; unknown prefix → 404 `{error:{message}}`; fake adapter registered in-test → paste complete e2e through `gateway.fetch` (login → start → complete `{token}` → status connected); without `OAUTH_ENCRYPTION_KEY` → 503 message "set OAUTH_ENCRYPTION_KEY secret first" (Review Focus #3).
- [ ] **Step 2: Run → FAIL** (`npm test -- test/admin-oauth.test.ts`)
- [ ] **Step 3: Implement** handlers + route block. 503 guard: when `env.DB` exists but `importAesKey(env)` is null on any write/read path → `OAuthError(503, "set OAUTH_ENCRYPTION_KEY secret first")`.
- [ ] **Step 4: Run → PASS** (full suite: `npm test` — existing 130 stay green)
- [ ] **Step 5: Commit** — `git commit -m "feat(oauth): admin oauth api routes"`

---

### Task 7: trae + devin-desktop paste adapters

**Files:**
- Create: `src/oauth/providers/registry.ts`, `src/oauth/providers/trae.ts`, `src/oauth/providers/devin-desktop.ts`
- Modify: `src/oauth/engine.ts` (call `registerAdapter` for each registry entry at module init)
- Test: `test/oauth-providers-paste.test.ts`

**Interfaces:**
- Consumes: `OAuthAdapter` (Task 4).
- Produces: `OAUTH_ADAPTERS: OAuthAdapter[]` in `registry.ts` (imports the adapter files; grows every provider task; engine imports it and registers each — no cycle: adapters import only `types.ts`).

Adapter specs (verbatim from recon):

**trae** (`prefix:"trae"`, `flowMode:"paste"`, `authKind:"paste"`, instructions = TRAE_CONFIG.tokenNote quoted in the File Structure section):
- default paste handling (`access_token` wrapper, engine-side); `mapTokens(tokens)`: `accessToken: tokens.accessToken ?? tokens.access_token`, `refreshToken: tokens.refreshToken ?? null`, `expiresIn: tokens.expiresIn ?? 14*86400`, meta: `{ webId, bizUserId, userUniqueId, scope:"marscode-us", tenant:"marscode", region:"US-East", aiRegion, appLanguage:"en", appVersion:"1.0.0.1229", userRegion:"US", userIdentity:"Free", authMethod:"imported" }` — each `tokens.x ?? tokens.x_snake ?? ""` per recon field list (webId/web_id, bizUserId/biz_user_id, userUniqueId/user_unique_id, aiRegion/ai_region/region, appLanguage/app_language, appVersion/app_version, userRegion/user_region, userTimezone/user_timezone optional, userIdentity/user_identity).

**devin-desktop** (`prefix:"devin-desktop"`, `flowMode:"paste"`, instructions: "Paste the Devin session token from an authenticated Devin session (browser sign-in)."):
- `importToken(raw)`: token = raw.access_token as string; trim; empty → throw "Token is empty"; length <16 → throw "Token is too short"; normalize: if not starting with `devin-session-token$`, prefix it exactly once; return `{access_token: normalized}`.
- `mapTokens`: `{accessToken: tokens.access_token, refreshToken: null, expiresIn: null}`.
- Browser-PKCE variant (supportsBrowserPkce in OmniRoute) → **deferred to Plan 2**; record in ledger.

- [ ] **Step 1: Write failing tests** — trae: snake/camel field mapping (feed `{access_token:"jwt", web_id:"w1"}` → meta.webId "w1", expiresIn 1209600, accessToken "jwt"); explicit expiresIn wins. devin: short token throws; bare token gets `devin-session-token$` prefix; already-prefixed token stays single-prefixed. Both registered: `getAdapter("trae")` non-null.
- [ ] **Step 2: Run → FAIL**
- [ ] **Step 3: Implement** the three files + engine registration.
- [ ] **Step 4: Run → PASS**
- [ ] **Step 5: Commit** — `git commit -m "feat(oauth): trae + devin-desktop paste adapters"`

---

### Task 8: cline paste-code adapter

**Files:**
- Create: `src/oauth/providers/cline.ts`; modify `registry.ts` (+ import/register)
- Test: `test/oauth-providers-cline.test.ts`

**Interfaces:**
- Produces: adapter `prefix:"cline"`, `flowMode:"paste-code"`, config = CLINE_CONFIG (values in File Structure section); no `redirectUri` (engine default `${origin}/admin` — the code arrives pasted, no server callback).

Adapter spec (verbatim from recon):
- `buildAuthUrl(config, redirectUri)`: `URLSearchParams({client_type:"extension", callback_url: redirectUri, redirect_uri: redirectUri})` → `${config.authorizeUrl}?${params}` (no PKCE/state — adapter signature ignores the extra args).
- `exchangeToken(config, code)`: **first** try embedded decode: `decodeURIComponent` (tolerate failure) → base64-pad to multiple of 4 → `atob` → take substring through the **last** `}` → `JSON.parse` → require `tokenData.accessToken` string else throw → return `{access_token, refresh_token, email, firstName, lastName, expires_at}`. If anything throws → **fallback**: POST `config.tokenExchangeUrl` JSON `{grant_type:"authorization_code", code, client_type:"extension", redirect_uri}`; !ok → throw `Cline token exchange failed: ${await response.text()}`; return `{access_token: data.data?.accessToken ?? data.accessToken, refresh_token: data.data?.refreshToken ?? data.refreshToken, email: data.data?.userInfo?.email ?? "", expires_at: data.data?.expiresAt ?? data.expiresAt}`.
- `mapTokens(tokens)`: `{accessToken, refreshToken, expiresIn: tokens.expires_at ? Math.floor((new Date(tokens.expires_at).getTime() - Date.now())/1000) : 3600, name: fullName || tokens.email || null, email: tokens.email, meta: {firstName, lastName}}` where fullName = `[firstName, lastName].filter(Boolean).join(" ").trim()`.
- Refresh: **deferred** (refreshUrl shape unrecon'd — Plan 2 recon step; ledger TODO).

- [ ] **Step 1: Write failing tests** (fetch mock): embedded path — feed the base64 of `{"accessToken":"at","refreshToken":"rt","email":"e@x.com","firstName":"A","lastName":"B","expiresAt":"2030-01-01T00:00:00Z"}` (URI-encoded variant too) → tokens mapped, name "A B"; garbage code → fallback POST called with the exact body, mocked `{data:{accessToken:"at2"}}` → accessToken "at2"; fallback !ok → throws message.
- [ ] **Step 2: Run → FAIL**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run → PASS**
- [ ] **Step 5: Commit** — `git commit -m "feat(oauth): cline paste-code adapter"`

---

### Task 9: kilocode + freebuff device adapters

**Files:**
- Create: `src/oauth/providers/kilocode.ts`, `src/oauth/providers/freebuff.ts`; modify `registry.ts`
- Test: `test/oauth-providers-device.test.ts`

**Interfaces:**
- Produces:
  - **kilocode** `prefix:"kilocode"`, `flowMode:"device"`, config KILOCODE_CONFIG:
    - `requestDeviceCode`: POST `initiateUrl`, `Content-Type: application/json`; !ok: 429 → throw "Too many pending authorization requests. Please try again later.", else throw `Device auth initiation failed: ${await response.text()}`; json `{code, verificationUrl, expiresIn}` → `{device_code: code, user_code: code, verification_uri: verificationUrl, verification_uri_complete: verificationUrl, expires_in: expiresIn ?? 300, interval: 3}`.
    - `pollToken(config, deviceCode)`: GET `${pollUrlBase}/${deviceCode}`; 202 → `{ok:false, data:{error:"authorization_pending"}}`; 403 → `{ok:false, data:{error:"access_denied", error_description:"Authorization denied by user"}}`; 410 → `{ok:false, data:{error:"expired_token", error_description:"Authorization code expired"}}`; other !ok → `{ok:false, data:{error:"poll_failed", error_description:"Poll failed: <status>"}}`; ok json `{status:"approved", token, userEmail}` + token → `{ok:true, data:{access_token: token, _userEmail: userEmail}}`; else pending.
    - `mapTokens`: `{accessToken, refreshToken: null, expiresIn: null, email: tokens._userEmail}`.
  - **freebuff** `prefix:"freebuff"`, `flowMode:"device"`, config FREEBUFF_CONFIG:
    - `fingerprintId()` = `codebuff-cli-` + 8 base64url chars of 6 random bytes (`crypto.getRandomValues`).
    - `requestDeviceCode`: POST `codeUrl` JSON `{fingerprintId}`; !ok → throw `Freebuff login URL request failed (<status>)`; json needs string `loginUrl`, string `fingerprintHash`, parseable `expiresAt` (ISO date or epoch-ms digits) else throw "Freebuff login URL response is missing required fields"; `device_code` = base64url(JSON `{fingerprintId, fingerprintHash, expiresAt}`) (btoa, not Buffer); `user_code` = fingerprintId minus `codebuff-cli-`; `expires_in` = max(1, floor((expiresAtMs - now)/1000)); `interval` = 5.
    - `pollToken`: decode device_code (malformed → `{ok:false, data:{error:"invalid_request", error_description:"Malformed Freebuff login state"}}`); GET `statusUrl?fingerprintId=&fingerprintHash=&expiresAt=`; !ok: expired (expiresAtMs ≤ now) → `expired_token` "Freebuff login expired"; 429/5xx → `slow_down`; else `authorization_pending`. ok: read `text()` once, try JSON; `user.authToken` string → `{ok:true, data:{access_token: authToken, _userId?, _userEmail?, _userName?, _fingerprintId}}`; else expired-check then pending.
    - `mapTokens`: `{accessToken, refreshToken: null, expiresIn: null, email: tokens._userEmail, name: tokens._userName, meta: {userId?, fingerprintId?}}` (optional keys only when present).

- [ ] **Step 1: Write failing tests** (fetch mock): kilocode initiate ok → device response shape (interval 3); initiate 429 → exact message; poll 202/403/410 → pending/denied/expired; approved → ok + email. freebuff: requestDeviceCode with mocked `{loginUrl, fingerprintHash, expiresAt:"2030-01-01T00:00:00Z"}` → device_code decodes back to the three fields, user_code strips prefix; poll ok + `user.authToken` → access_token + `_fingerprintId`; poll 429 → slow_down; malformed device_code → invalid_request.
- [ ] **Step 2: Run → FAIL**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run → PASS**
- [ ] **Step 5: Commit** — `git commit -m "feat(oauth): kilocode + freebuff device adapters"`

---

### Task 10: codebuddy-cn + codebuddy-intl device adapters

**Files:**
- Create: `src/oauth/providers/codebuddy.ts` (shared flow + both adapters, mirroring OmniRoute `codebuddyDeviceAuth.ts`); modify `registry.ts`
- Test: `test/oauth-providers-codebuddy.test.ts`

**Interfaces:**
- Produces: adapters `prefix:"codebuddy-cn"` (platform `CLI`, domain `copilot.tencent.com`) and `prefix:"codebuddy-intl"` (platform `ide`, domain `www.codebuddy.ai`), both `flowMode:"device"`.
- **Recon step first (one action):** fetch OmniRoute `providerHeaderProfiles.ts` to pin exact `CODEBUDDY_CN_USER_AGENT` / `CODEBUDDY_INTL_USER_AGENT` values (try `packages/`, `src/lib/open-sse/`, `src/open-sse/` listings under ref `release/v3.8.54`; the exact import path in constants/oauth.ts is `@omniroute/open-sse/config/providerHeaderProfiles.ts`). If unfindable, use literal `CodeBuddy-CLI/1.0` (cn) / `CodeBuddy-IDE/1.0` (intl) and record the gap in the ledger.

Adapter spec (verbatim from recon):
- `requestDeviceCode(config)`: POST `${config.stateUrl}?platform=${encodeURIComponent(config.platform)}`; headers `Content-Type: application/json, Accept: application/json, User-Agent: <config.userAgent>, X-Requested-With: XMLHttpRequest, X-Domain: <domain>, X-No-Authorization: true, X-No-User-Id: true, X-Product: SaaS`; body `JSON.stringify({platform})`. !ok → throw `CodeBuddy state request failed (<status>)`. Envelope `{code: 0, data: {state, authUrl | url}}` required → `{device_code: state, user_code: state, verification_uri: authUrl, verification_uri_complete: authUrl, expires_in: 600, interval: max(1, floor(pollInterval/1000))}` (5); bad envelope → throw `CodeBuddy state error: ${msg || "no state in response"}`.
- `pollToken(config, deviceCode)`: GET `${config.tokenUrl}?state=${encodeURIComponent(deviceCode)}` with the same header set (+ `X-No-Enterprise-Id: true`, `X-No-Department-Info: true`); !ok → `{ok:false, data:{error:"request_failed"}}`; envelope `code === 0 && data.accessToken` → `{ok:true, data:{access_token, refresh_token: data.refreshToken ?? "", token_type: data.tokenType ?? "Bearer", expires_in: data.expiresIn}}`; else `{ok:false, data:{code, msg}}` (engine treats non-standard errors as terminal — pending deleted).
- `mapTokens`: `{accessToken, refreshToken, expiresIn: tokens.expires_in ?? 86400}`.
- Refresh (config.refreshUrl exists): **deferred** — unrecon'd shape; ledger TODO (same as Task 5 note).

- [ ] **Step 1: Recon step** — fetch the header-profiles file (or record fallback decision) **before** writing the test that pins the UA.
- [ ] **Step 2: Write failing tests** — mocked `{code:0, data:{state:"s1", authUrl:"https://auth…"}}` → device response (interval 5); poll success → tokens + defaults (refresh "" → refreshToken ""; expires_in undefined → 86400); poll `{code:1, msg:"x"}` → ok:false data `{code:1, msg:"x"}`; cn vs intl hit their own stateUrl with their own platform/domain/UA.
- [ ] **Step 3: Run → FAIL**
- [ ] **Step 4: Implement.**
- [ ] **Step 5: Run → PASS**
- [ ] **Step 6: Commit** — `git commit -m "feat(oauth): codebuddy cn + intl device adapters"`

---

### Task 11: Forward integration (Bearer from token store)

**Files:**
- Modify: `src/providers.ts` — `ProviderConfig`: add `oauth?: boolean`, make `keySecret` optional (`keySecret?: string`). Do NOT add real provider entries yet (their endpoints/formats land with Plans 2–3; mechanism proven here with a fake).
- Modify: `src/forward.ts`
- Test: `test/oauth-forward.test.ts`

**Interfaces:**
- Consumes: `ensureFreshToken` (Task 5).
- Produces:
  - `class MissingTokenError extends Error { constructor(public prefix: string) { super(`OAuth provider '${prefix}' is not connected — connect it in the admin console (/admin).`) } }`
  - `forwardToProvider` behavior change: when `resolved.oauth === true` → skip `providerKey`; `const token = await ensureFreshToken(env, resolved.prefix)` inside try — `TokenExpiredError` → rethrow as `MissingTokenError` (same 400/skip-in-chain semantics); headers use `authorization: Bearer <token>` (bearer mode) or `authorization: Bearer` + existing anthropic header logic stays for non-oauth.
  - `forwardOr400`: catch `MissingTokenError` → meta.error `missing-token:<prefix>`, 400 `{error:{message}}`.

- [ ] **Step 1: Write failing tests** — register a fake oauth adapter + save a fresh token (store) for prefix `fakeoauth`; build a `Resolved` `{prefix:"fakeoauth", baseURL:"https://up.test", auth:"bearer", oauth:true, model:"m"}`; mock fetch; `forwardToProvider` → authorization header is `Bearer <decrypted token>`, no env key consulted. Expired token + refresh → refresh POST happens then forward carries the rotated token (vi.mock sequencing via two fetch mocks). Not connected → `forwardOr400` returns 400 with meta.error `missing-token:fakeoauth`. Existing API-key path regression: `forwardToProvider` with `oauth` undefined still uses `providerKey` (existing suite already pins this — run full suite).
- [ ] **Step 2: Run → FAIL** (`npm test -- test/oauth-forward.test.ts`)
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run → PASS** + full `npm test` green.
- [ ] **Step 5: Commit** — `git commit -m "feat(gateway): oauth bearer in forward path"`

---

### Task 12: Admin console OAuth UI

**Files:**
- Modify: `public/admin/index.html` (OAuth section in Overview tab, after the API-key provider grid)
- Modify: `public/admin/app.js` (loader + renderers + connect flows; vanilla JS, same patterns as existing code)
- Modify: `public/admin/app.css` (card styles)
- Test: `test/admin-ui-dom-oauth.test.ts` (reuse the fresh-Window happy-dom harness pattern from `test/admin-ui-dom.test.ts` — read that file first and mirror its Window-stubbing exactly)

**Interfaces:**
- Consumes: `/admin/api/oauth` JSON shapes (Task 6).
- Produces (DOM behavior the tests pin):
  - Overview tab renders an "OAuth Providers" grid: one card per adapter (prefix, flowMode badge, status line `connected · expires <date>` / `not connected` / `last error`).
  - `paste` card: textarea + "Connect" → `POST complete {token}` → reload → badge connected.
  - `paste-code` card: "Start login" → `POST start` → show authUrl as a link + code input + "Complete" → `POST complete {code}`.
  - `device` card: "Start login" → `POST start` → show `user_code` + verification link + auto-poll every `interval` sec (`setTimeout` chain; stop on connected/error/expired — Review Focus #5) → badge connected.
  - Disconnect button per connected card → `DELETE /admin/api/oauth/<prefix>` → reload.
  - Errors surface via existing `notify()` banner; no token material ever rendered (only masked prefix state — we never receive tokens back anyway).

- [ ] **Step 1: Write failing DOM tests**: card renders per mode; paste connect posts `{token}` to the right URL; paste-code start→complete posts `{code}`; device start renders user_code and issues poll GET; poll "connected" → status badge updates; poll "error" → loop stops (no further poll calls); disconnect → DELETE fired.
- [ ] **Step 2: Run → FAIL**
- [ ] **Step 3: Implement** HTML/CSS/JS.
- [ ] **Step 4: Run → PASS** (full suite green)
- [ ] **Step 5: Commit** — `git commit -m "feat(admin): oauth connect ui"`

---

### Task 13: Docs + final verification

**Files:**
- Modify: `README.md` (OAuth section: what Wave B Plan 1 adds, `wrangler d1 migrations apply freeai-gateway-db --remote` (adds 0003), `npx wrangler secret put OAUTH_ENCRYPTION_KEY` with `openssl rand -base64 32` guidance, per-provider connect how-to, note that forwarding for these 7 lands with Plans 2–3)
- Modify: `.superpowers/sdd/freeai-gateway-v2-admin-console/progress.md` (Wave B Plan 1 LANDED section: tasks, commits, deferred items — cline/codebuddy refresh shapes, devin browser-PKCE, codebuddy UA fallback decision)

- [ ] **Step 1: Full verification** — `npm test` (all green), `npm run typecheck` (clean).
- [ ] **Step 2: Local smoke (manual)** — `npx wrangler d1 migrations apply freeai-gateway-db --local`; `npm run dev`; login → OAuth cards render; paste connect with a dummy token → connected badge; disconnect clears. Record result in ledger.
- [ ] **Step 3: README + ledger updates.**
- [ ] **Step 4: Commit** — `git commit -m "docs(gateway): wave b plan 1 oauth guide"`

## Completion

Wave B Plan 1 complete when: full suite green + typecheck clean at final commit; 7 adapters registered and connectable from the console; forward path proven for oauth providers (mechanism); README + ledger updated. Then: whole-branch review (free-tier model subagent), fix pass, merge to main — same flow as Wave D. Plan 2 (standard OAuth batch) is written only after Plan 1 lands.

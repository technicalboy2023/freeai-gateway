# FreeAI Gateway — Plan v2: Admin Console (Wave D upgrade)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Full OmniRoute-style admin console on the existing free Cloudflare Worker — provider control, request logs, usage stats, fallback editor, playground — at ₹0, no card.

**Architecture:** Same single Worker serves API + console. Console UI = static assets (vanilla JS SPA, no build step). All console data in **D1** (free: 5GB, 100k writes/day). Runtime config (provider enable/disable, fallback chains) moves to D1 with env-var fallback. Keys stay in Worker secrets only. Admin protected by separate `ADMIN_PASSWORD` secret → HMAC-signed HttpOnly session cookie.

**Tech Stack:** Cloudflare Workers + D1 + Workers Static Assets, TypeScript, vanilla JS console, vitest.

**Spec:** Conversation-approved 2026-11-16: user wants "poora system control" console same as OmniRoute; chose D1 storage, all features, separate ADMIN_PASSWORD, console before OAuth. Phase A spec from v1 plan (repo `plans/freeai-gateway.md`).

## Roadmap (updated order)

```
Phase A  Tasks 1–8   (base gateway — v1 plan is authority; Task 1 DONE, Task 2 mid-flight)
Wave D   Tasks 9–16  (admin console — THIS PLAN)
Wave B   Tasks 17+   (28 OAuth providers — separate detailed plan AFTER console)
Phase C              (multimodal, no-auth providers — last)
```

## Global Constraints (inherited from v1 + new)

- TypeScript, Workers runtime, web-standard APIs only in src/.
- Provider keys ONLY in secrets (`wrangler secret put`), never in D1, never in UI, never in responses.
- D1 free tier only; D1 failures must NEVER break proxy traffic (config read → env fallback; log writes fire-and-forget).
- Admin auth: `ADMIN_PASSWORD` secret → cookie `admin_session`, HMAC-SHA256 signed, expiry ≤ 7d, HttpOnly, SameSite=Strict.
- Console UI: vanilla HTML/JS/CSS in `public/admin/`, no npm build step.
- Tests: vitest, stub D1/stub fetch; no real provider calls.
- Commits: `feat(gateway): ...` per task; repo plan v1 (`plans/freeai-gateway.md`) remains authority for Phase A Tasks 2–8.

## Interfaces

- `src/config.ts` (Task 9): `getSetting(env, key): Promise<string|null>` (D1 → env fallback), `setSetting(env, key, value): Promise<void>`, `SETTING_KEYS = { PROVIDERS_ENABLED: "providers_enabled", FALLBACK_CHAINS: "fallback_chains" }`. Binding name: `DB` (D1Database).
- `src/logging.ts` (Task 10): `logRequest(db, entry): Promise<void>` — swallows its own errors; entry `{ ts, provider, model, status, latencyMs, stream, chain, attempt, error }`.
- `src/admin/auth.ts` (Task 11): `checkAdmin(request, env): Promise<Response|null>` (null = proceed), `handleLogin(request, env)`, `handleLogout()`.
- `src/chat.ts` forwarder (produced in v1 Task 4): `forwardToProvider(resolved, body, env): Promise<Response>` — consumed by fallback (v1 Task 6) and playground (Task 14).
- Token format (Task 11): `"<expiryEpochMs>.<hexHmacSha256(key=ADMIN_PASSWORD, msg="admin:"+expiryEpochMs)>"`; valid only if HMAC matches AND expiry > now.

## Review Focus

- Admin API must never echo provider keys or ADMIN_PASSWORD (test buttons return status/latency only) → pinned in Task 12 tests.
- Tampered/expired/missing admin cookie → 401 (HMAC verify + expiry check) → Task 11 tests.
- D1 down/misconfigured must not 500 the proxy path (config read falls back to env; log write swallowed) → Task 9/10 tests.
- Disabled provider returns clean 4xx naming the provider, not a confusing upstream error → Task 12 + integration in Task 15 smoke.
- Playground bypasses GATEWAY_KEY but requires admin cookie → Task 14 tests.

---

## Wave D Tasks

### Task 9: D1 + config store

**Files:**
- Modify: `wrangler.jsonc` — add `"d1_databases": [{ "binding": "DB", "database_name": "freeai-gateway-db", "database_id": "TODO-wrangler-d1-create" }]`
- Create: `migrations/0001_init.sql`
- Create: `src/config.ts`
- Test: `test/config.test.ts`

**Interfaces:** Consumes D1 binding `env.DB`. Produces `getSetting`/`setSetting`/`SETTING_KEYS` (see Interfaces above). Later tasks (12, 13) read/write via this module only — no direct D1 SQL outside migrations/logging.

**Steps:**
- [x] Write migration `migrations/0001_init.sql`:

```sql
CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS request_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
  status INTEGER NOT NULL, latency_ms INTEGER, stream INTEGER DEFAULT 0,
  chain TEXT, attempt INTEGER, error TEXT
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON request_logs (ts DESC);
CREATE INDEX IF NOT EXISTS idx_logs_provider ON request_logs (provider);
```

- [x] Write failing test `test/config.test.ts` with a stub D1Database object (`prepare(sql)` → `{ bind(...): { first(), run() } }` capturing SQL/params):
  - `getSetting` returns D1 value when row exists
  - falls back to `env[key]` when D1 row missing
  - returns `null` when neither
  - `setSetting` upserts (INSERT ... ON CONFLICT(key) DO UPDATE)
- [x] Run `npm test` — expect FAIL (module missing)
- [x] Implement `src/config.ts` per Interfaces
- [x] Run `npm test` — expect PASS; `npm run typecheck` clean
- [x] Commit: `feat(gateway): d1 config store`

**Ruling (recorded):** config precedence D1 > env > built-in default. v1 Task 6's env-based `FALLBACK_CHAINS` stays working unchanged (env fallback) until Wave D wires D1 in Tasks 12–13; no rework of Phase A.

### Task 10: Request logging hook

**Files:**
- Create: `src/logging.ts`
- Modify: `src/chat.ts`, `src/messages.ts`, `src/fallback.ts` — after upstream response headers received: `ctx.waitUntil(logRequest(env.DB, {...}))`
- Test: `test/logging.test.ts`

**Interfaces:** Consumes `env.DB`, `Resolved` (v1 Task 2), forwarder call sites. Produces `logRequest(db, entry)`.

**Steps:**
- [x] Failing test `test/logging.test.ts` (stub DB captures row):
  - logs ts/provider/model/status/latencyMs/stream/chain/attempt/error fields
  - `logRequest` rejects are swallowed (stub DB whose `run()` throws → `logRequest` still resolves)
- [x] Run `npm test` — FAIL
- [x] Implement `src/logging.ts`; wire `ctx.waitUntil` into the three proxy paths (log at response-start; `status` = upstream status, `latencyMs` = time-to-headers, `chain/attempt` filled by fallback path, `error` on 5xx/body-read failure)
- [x] Run `npm test` — PASS; typecheck clean
- [x] Commit: `feat(gateway): request logging`

### Task 11: Admin auth (password → session cookie)

**Files:**
- Create: `src/admin/auth.ts`
- Modify: `src/env.ts` — add `ADMIN_PASSWORD: string` to `Env`
- Modify: `src/index.ts` — route `/admin/api/login`, `/admin/api/logout`, `/admin/api/me`
- Test: `test/admin-auth.test.ts`

**Interfaces:** Consumes `ADMIN_PASSWORD` secret. Produces `checkAdmin`/`handleLogin`/`handleLogout` (see Interfaces above).

**Steps:**
- [x] Failing test `test/admin-auth.test.ts`:
  - login with correct password → 200 + `Set-Cookie: admin_session=…; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800`
  - login wrong password → 401 JSON; no cookie
  - `ADMIN_PASSWORD` unset → 503 JSON "ADMIN_PASSWORD not configured"
  - `checkAdmin` with valid fresh cookie → null (proceed)
  - tampered token, expired token, missing cookie → 401 JSON
  - logout → clears cookie
- [x] Run `npm test` — FAIL
- [x] Implement `src/admin/auth.ts` (HMAC via `crypto.subtle`; token per Interfaces)
- [x] Run `npm test` — PASS; typecheck clean
- [x] Commit: `feat(gateway): admin auth`

### Task 12: Admin providers API

**Files:**
- Create: `src/admin/providers.ts`
- Modify: `src/index.ts` — routes under `/admin/api/providers*`, all behind `checkAdmin`
- Test: `test/admin-providers.test.ts`

**Interfaces:** Consumes `checkAdmin`, `list()` (v1 Task 2), `getSetting`/`setSetting` (`SETTING_KEYS.PROVIDERS_ENABLED`), forwarder `forwardToProvider`. Produces JSON shapes consumed by Task 15 UI.

**Steps:**
- [x] Failing tests (stub env with fake secrets, stub DB):
  - `GET /admin/api/providers` → registry list + per-provider `{ enabled, keyConfigured: !!env[keySecret], freeModels }`; response contains NO key material
  - disabled-by-D1 provider shows `enabled: false`
  - `POST /admin/api/providers/nvidia/toggle {enabled:false}` → 200; writes `providers_enabled` map
  - toggle unknown prefix → 404
  - `POST /admin/api/providers/groq/test` (mock fetch) → `{ ok, status, latencyMs }`; never includes key; upstream error → `ok:false`
  - any of these without valid admin cookie → 401
- [x] Run `npm test` — FAIL
- [x] Implement; enabled-check integration: proxy path rejects disabled providers with 4xx naming provider
- [x] Run `npm test` — PASS; typecheck clean
- [x] Commit: `feat(gateway): admin providers api`

### Task 13: Admin fallbacks + logs + stats API

**Files:**
- Create: `src/admin/ops.ts`
- Modify: `src/index.ts` — `/admin/api/fallbacks`, `/admin/api/logs`, `/admin/api/stats` behind `checkAdmin`
- Test: `test/admin-ops.test.ts`

**Interfaces:** Consumes `SETTING_KEYS.FALLBACK_CHAINS`, `logRequest` table. Produces JSON for Task 15 UI. Chain shape: `[{ name: string, providers: string[] }]`.

**Steps:**
- [x] Failing tests:
  - `GET /admin/api/fallbacks` → D1 value, else env `FALLBACK_CHAINS`, else `{ "default": ["groq","gemini"] }` shape
  - `PUT` valid chains → 200 + persisted; invalid (provider prefix unknown in registry) → 400 naming the bad prefix
  - `GET /admin/api/logs?limit=50` → rows desc by ts
  - `GET /admin/api/stats` → per-provider `{ requests, errors, avgLatencyMs }` (7d window, SQL GROUP BY)
  - unauth → 401
- [x] Run `npm test` — FAIL
- [x] Implement
- [x] Run `npm test` — PASS; typecheck clean
- [x] Commit: `feat(gateway): admin ops api`

### Task 14: Playground API

**Files:**
- Create: `src/admin/playground.ts`
- Modify: `src/index.ts` — `POST /admin/api/playground` behind `checkAdmin`
- Test: `test/admin-playground.test.ts`

**Interfaces:** Consumes `checkAdmin`, `resolve`, `forwardToProvider`.

**Steps:**
- [x] Failing tests:
  - valid admin cookie + `{model:"groq/llama-3.3-70b", messages:[…], stream:false}` → forwarded with GROQ key, response passed through (NO `GATEWAY_KEY` check)
  - `stream:true` → SSE passthrough
  - without admin cookie → 401 (even with correct gateway key absent/present)
- [x] Run `npm test` — FAIL
- [x] Implement
- [x] Run `npm test` — PASS; typecheck clean
- [x] Commit: `feat(gateway): admin playground`

### Task 15: Console UI (SPA)

**Files:**
- Create: `public/admin/index.html`, `public/admin/app.js`, `public/admin/app.css`
- Modify: `wrangler.jsonc` — add `"assets": { "directory": "./public" }`
- Modify: `src/index.ts` — ensure `/admin/api/*` wired (assets serve `/admin` HTML automatically)
- Test: `test/admin-ui.test.ts`

**Steps:**
- [x] Failing test: `GET /admin` → 200 `text/html`; `GET /admin/app.js` → 200 JS; all `/admin/api/*` without cookie → 401
- [x] Run `npm test` — FAIL
- [x] Build vanilla SPA (dark theme): login overlay; tabs — Overview (provider cards: on/off switch, Test button, key-configured dot), Logs (table, provider filter, auto-refresh 5s), Stats (per-provider counts), Fallbacks (chain editor: add/remove/reorder), Playground (model input `provider/model`, message box, stream toggle, response pane)
- [x] Run `npm test` — PASS; typecheck clean
- [x] Manual smoke: `npm run dev` → login, toggle provider, see log row, playground round-trip
- [x] Commit: `feat(gateway): admin console ui`

### Task 16: Docs

**Files:** Modify: `README.md`

**Steps:**
- [x] README sections: `wrangler d1 create freeai-gateway-db` + migrations apply (local + remote), `npx wrangler secret put ADMIN_PASSWORD`, console tour screenshots-less (URL `https://<worker>/admin`), security notes
- [x] Commit: `docs(gateway): admin console guide`

## Wave D Completion

`npm test` all green; `npm run typecheck` clean; manual smoke list in Task 15 done; final whole-branch review per executing-plans.

## Wave B (OAuth, 28 providers) — outline only

Detailed plan AFTER console ships. Framework: login dashboard INSIDE this console (`/admin/providers` gets OAuth login buttons), KV + AES-GCM token store, refresh engine, per-provider adapters. Waves: B1 paste-token (trae, agy, devin-desktop, freebuff, kilocode, cline, codebuddy), B2 device-code (github, ghe-copilot, kimi-coding, muse-code, workbuddy, freebuff), B3 PKCE (claude, codex, xai-oauth, grok-cli, cursor, openference, clinepass), B4 hard (antigravity, amazon-q, zed-hosted, gitlab-duo). Excluded: kiro (ToS), devin-cli/qoder/zed local-only.

## Phase C — outline only

Multimodal passthrough (image/video bodies), no-auth providers, stats charts polish.

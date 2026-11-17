# Wave B — Plan 2: Standard OAuth Batch (13 Providers) + Plan-1 Carry-overs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the 13 recon-verified standard-OAuth providers (user-approved batch 2026-11-16) onto the Plan-1 OAuth engine, plus the Plan-1 review carry-overs (engine extensions, typed error, auto-callback route, pending-state encryption, refresh shapes for cline/codebuddy, poll-chain liveness, slow_down backoff, kilocode envelope validation, codebuddy msg/code surfacing, D1 miniflare test, handleTestProvider oauth branch). The 13, by the flowMode our engine actually ships: **device-mode adapters (8)** — github, ghe-copilot, kimi-coding, muse-code, minimax-code, workbuddy, grok-cli, cursor (grok-cli and cursor were user-categorized under the PKCE/paste bucket but port as device flows; both also accept paste-token imports); **paste-code adapters (4)** — claude, codex, xai-oauth, openference; **paste alias (1)** — clinepass (reuses the Plan-1 cline adapter flow under its own prefix).

**Architecture:** Extend the generic `src/oauth/` core once (Task 1: `postExchange` hook, `mapTokens(tokens, extra?, priorMeta?)`, `requestDeviceCode(config, codeChallenge?, startParams?)`, `pollToken(config, deviceCode, codeVerifier?, startParams?)`, `refresh(config, refreshToken, meta?)`, per-start `parseStartParams`, encrypted pending extras), then add one thin adapter file per provider under `src/oauth/providers/` (OmniRoute `release/v3.8.54` modules ported 1:1 to web-standard APIs). Console cards render automatically from the adapter registry.

**Tech Stack:** Cloudflare Workers (web-standard APIs only), D1, vanilla admin SPA (no build step), vitest.

**Spec:** `docs/superpowers/specs/2026-11-16-waveb-oauth-design.md` (approved). Predecessor: `docs/superpowers/plans/2026-11-16-waveb-plan1-oauth-engine-and-simple-providers.md` (landed, merged `4a22b37`). Forwarding for any provider is a separate plan (user decision 2026-11-16).

**Recon source (first-hand, 2026-11-16):** OmniRoute `release/v3.8.54` sparse checkout at `C:\Users\ankush\AppData\Local\Temp\opencode\omniroute` — every value below was read verbatim from `src/lib/oauth/**`, `open-sse/config/**`, `open-sse/services/tokenRefresh/**`, `open-sse/services/museCodeAuth.ts`, `open-sse/utils/publicCreds.ts`, `open-sse/executors/minimaxCodeGateway.ts`, `src/lib/providers/validation/anthropicFormat.ts`. Do NOT re-fetch; port from this doc. If a task needs a value not pinned here, re-read that one file from the sparse checkout.

## Global Constraints (apply to every task)

1. **TDD:** every task starts with failing tests (RED), then implementation (GREEN). Suite green + `npm run typecheck` clean before every commit. Run: `npm test`, single file: `npm test -- test/<file>.test.ts`.
2. **Web-standard APIs only** in `src/` (Request/Response/fetch/URL/crypto.subtle/TextEncoder). No `node:crypto`, no `Buffer`, no `process`. JWT payload decoding uses `atob` + URL-safe base64 normalization (padding repair per codex/xai pattern below).
3. **Tokens only in D1, AES-GCM encrypted** via `src/oauth/crypto.ts`. Pending flow state (state / codeVerifier / device_code / extra) also encrypted (Task 1). Never log token material.
4. **Admin-gated:** all OAuth API routes stay behind `checkAdmin` EXCEPT the one deliberate public route: the state-matched auto-callback `GET /admin/oauth/:prefix/callback` (Task 2 — USER DECISION 2026-11-16; the secret single-use pending state + pending TTL are its gate). New API routes follow `src/admin/oauth.ts` guards.
5. **No cron → refresh-on-use** (`src/oauth/refresh.ts` `ensureFreshToken`); refresh results merge with the existing row (never clobber label/meta/refresh grant). A rejected refresh records a PROVIDER-SPECIFIC `last_error` text (each adapter owns its message — e.g. "Muse Code key mint failed (HTTP 429)."), never a generic "refresh rejected"; transient failures leave the card at reconnect-required until the next successful use (USER DECISION 2026-11-16 — accept, don't suppress).
6. **Exact pinned constants:** copy URLs/headers/client-ids/scope strings from this doc verbatim. No paraphrasing identifiers.
7. **Public client IDs are literals in our repo** (they are public-by-design OAuth native-app clients; OmniRoute XOR-masks them only to appease its own scanners). We store them as plain constants, with an optional env override per provider mirroring OmniRoute's env priority where the plan pins one.
8. **One connection per provider** (single-operator gateway). Adapters register in `src/oauth/providers/registry.ts`; console renders automatically.
9. **Failure surfaces:** `OAuthError(status, message)` from the engine; store-class errors (`DbMissingError`) keep their HTTP class. Poll answers stay non-fatal until terminal.
10. **Test harness conventions from Plan 1:** DOM tests with function-valued routes + 200-always fetch stub; fake timers with microtask flush for poll chains; assertion convention `connected · expires`. Device/poll tests stub `savePending`/`getPending` via D1 stub unless using miniflare (Task 3).

## Review Focus (whole-plan invariants — check at review time)

- **RF-1 Pending flow state encrypted at rest:** every `oauth_pending` TEXT column write goes through the `enc:v1:` codec (Task 1); a raw `SELECT` in a test must not find plaintext `code_verifier`/`device_code`/`state`/gheUrl.
- **RF-2 Refresh never degrades:** every refresh path either merges (`saveToken` with `connectedAt: row.connectedAt`) or throws `TokenExpiredError` after recording `last_error`. New adapters' `refresh` hooks accept `meta` and use it (gheUrl, kimi deviceId, muse dca).
- **RF-3 `priorMeta` contract:** connect path passes no priorMeta; refresh path passes `row.meta`. claude `mapTokens` preserves `meta.cliUserID` from priorMeta and generates a fresh one only when absent (test pins both branches).
- **RF-4 PKCE-on-device threading:** minimax `pollToken` receives the verifier stored at device start; the engine passes `pending.codeVerifier` — the challenge/verifier pair must originate from the same `generatePkce` call (test pins: requestDeviceCode body carries the challenge, pollToken body carries the verifier).
- **RF-5 Paste-import security:** `sk-ant-oat` (claude) and grok `auth.json`/JWT imports validate BEFORE store; a bad paste produces 400 and writes NO row (test pins row absence).
- **RF-6 Engine extension backward compat:** Plan-1 adapters (trae, devin-desktop, cline, kilocode, freebuff, codebuddy-cn, codebuddy-intl) must still pass their Plan-1 tests unchanged after Task 1–2 signature extensions (old optional params default undefined).

---

## Shared recon constants (verbatim, ported per task)

### Public OAuth client IDs (OmniRoute `.env.example` + `publicCreds.ts` decode, all public-by-design)

| Provider key | client_id |
|---|---|
| claude | `9d1c250a-e61b-44d9-88ed-5944d1962f5e` |
| codex | `app_EMoamEEZ73f0CkXaXp7hrann` |
| kimi-coding | `17e5f671-d194-4dfb-9706-5516cb48c098` |
| github / ghe-copilot | `Iv1.b507a08c87ecfe98` |
| grok-cli / xai-oauth (same public xAI client) | `b1a00492-073a-47ea-816f-4c329264a828` |
| openference | `omniroute` |
| minimax-code | `mcode-public` |
| muse-code | `1031625952748946` |

### Claude (`CLAUDE_CONFIG`)
- authorize `https://claude.ai/oauth/authorize`; token `https://api.anthropic.com/v1/oauth/token`; redirectUri `https://platform.claude.com/oauth/code/callback` (constant; loopback never runs on workers.dev — user pastes the code shown at the provider callback URL); scopes `org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers` (joined with spaces); S256.
- `buildAuthUrl` params: `response_type=code`, `client_id`, `redirect_uri`, `scope`, `code_challenge`, `code_challenge_method=S256`, **`code=true`**, **`prompt=login`** (anti session-takeover, verbatim), `state`.
- Token exchange body: `grant_type=authorization_code`, `client_id`, `code`, `redirect_uri`, `code_verifier`. Claude's pasted code may arrive as `code#state` — split on `#`, use part before it.
- postExchange bootstrap: GET `https://api.anthropic.com/api/claude_cli/bootstrap`, headers `Authorization: Bearer <access>`, `Accept: application/json`, `User-Agent: claude-cli/2.1.7 (external, cli)`, `anthropic-beta: oauth-2025-04-20`, 10s timeout; non-2xx → null (best-effort, never blocks). Response fields read: `account_uuid`, `email`, `organizationName`, `organizationRole`.
- meta: `cliUserID` = random 32-byte hex (2 hex chars per byte → 64 hex chars), "generated once at provisioning; preserved across token refresh" → priorMeta contract (RF-3). Bootstrap extras → meta `account_uuid`, `email`, `organizationName`, `organizationRole`; label = email ?? account_uuid.
- Setup-token import (paste mode): token prefix `sk-ant-oat` required. Live-validate BEFORE store: POST `https://api.anthropic.com/v1/messages`, headers `Authorization: Bearer <token>`, `anthropic-version: 2023-06-01`, `anthropic-beta: oauth-2025-04-20`, `Content-Type: application/json`, body `{ model: "claude-haiku-4-5-20251001", max_tokens: 1, messages: [{ role: "user", content: "test" }] }`. 401/403 → reject "Invalid OAuth token"; ≥500 → reject "Provider unavailable (<status>)"; else accept. No refresh grant (1-year token).
- Refresh (OAuth tokens): POST token endpoint, form: `grant_type=refresh_token`, `refresh_token`, `client_id`; headers form-urlencoded + `Accept: application/json` + `anthropic-beta: oauth-2025-04-20`; rotate-in `refresh_token || old`.

### Codex (`CODEX_CONFIG`)
- authorize `https://auth.openai.com/oauth/authorize`; token `https://auth.openai.com/oauth/token`; scope `openid profile email offline_access`; S256; extraParams `id_token_add_organizations=true`, `codex_cli_simplified_flow=true`, `originator=codex_cli_rs`, `prompt=login`.
- Exchange body: `grant_type=authorization_code`, `client_id`, `code`, `redirect_uri`, `code_verifier`. (No loopback constant in OmniRoute — its dashboard uses per-session redirect; we use the provider paste-code pattern: redirectUri constant NOT sent — OmniRoute codex has no `redirectUri` config; buildAuthUrl sends whatever the engine resolves. For us: **do not set adapter.redirectUri**; the engine resolves `{origin}/admin/oauth/codex/callback` after Task 2's builder-b3 change — codex is the one adapter this plan whose redirect actually lands back on the gateway (public state-matched callback).)
- postExchange: decode `id_token` JWT payload (base64url→JSON). Custom claim at `https://api.openai.com/auth` → `chatgpt_account_id`, `chatgpt_plan_type`, `chatgpt_user_id`, `organizations[] { id, is_default, role, title }`. Workspace selection: planType team/chatgptteam → `chatgpt_account_id`; else a non-default org with title containing team/business/workspace/org or role admin/member → use that org id and planType "team"; else `chatgpt_account_id`. meta: `workspaceId`, `workspacePlanType`, `chatgptUserId`, `organizations` (or null). label = email.
- Refresh: standard form grant at token endpoint, `grant_type=refresh_token`, `refresh_token`, `client_id` — **never include `scope`** (re-scope invalidates sibling refresh-token families). Default `standardRefresh` already omits scope → no custom hook. Terminal errors: `refresh_token_reused`, `invalid_grant`, `token_expired`, `invalid_token`, any 401.

### xai-oauth (`XAI_OAUTH_CONFIG`)
- authorize `https://auth.x.ai/oauth2/authorize`; token `https://auth.x.ai/oauth2/token`; scope `openid profile email offline_access grok-cli:access api:access`; S256; loopback 56121 `/callback` host 127.0.0.1 (dead on workers.dev → paste-code; the exchange MUST send the SAME `redirect_uri` string the user saw, i.e. `http://127.0.0.1:56121/callback` — adapter sets `redirectUri` to this constant so the engine does not substitute our origin).
- **`pkceVerifierBytes: 96`** (96-byte verifier → 128 base64url chars; engine's `generatePkce(96)`).
- buildAuthUrl params: `response_type=code`, `client_id`, `redirect_uri`, `scope`, `code_challenge`, `code_challenge_method=S256`, `state`, `nonce=<32 hex random>`, `plan=generic`, `referrer=cli-proxy-api`.
- Exchange body: `grant_type=authorization_code`, `client_id`, `code`, `redirect_uri`, `code_verifier`.
- mapTokens: decode `id_token` payload → `email` (or `preferred_username`), `name`; meta `scope` (tokens.scope || config.scope), `tokenType` (tokens.token_type || "Bearer"). label = name || email.
- Refresh: standard form grant (client_id only) → default `standardRefresh` works.

### grok-cli (device primary + paste import)
- Device: issuer `https://auth.x.ai`; device-code `https://auth.x.ai/oauth2/device/code`; token `https://auth.x.ai/oauth2/token`; scope = 10 scopes joined with spaces: `openid profile email offline_access grok-cli:access api:access conversations:read conversations:write workspaces:read workspaces:write` (legacy wider set on `GROK_CLI_CONFIG`); device request body `client_id`, `scope`, `referrer=grok-build`; headers `Accept: application/json`, `Content-Type: application/x-www-form-urlencoded`, `x-grok-client-version: 1.0.41`, `x-grok-client-surface: ui`.
- Device response validation: `device_code`, `user_code`, `verification_uri` all strings required; `user_code` matches `/^[A-Za-z0-9-]+$/`; verification URLs must be `https:` or `http:` on `localhost`/`127.0.0.1` (reject control chars ≤0x1F/0x7F); defaults `expires_in` 1800, `interval` 5.
- Poll body: `client_id`, `device_code`, `grant_type=urn:ietf:params:oauth:grant-type:device_code` (same OAuth headers).
- Browser-PKCE variant (`grok-cli-oauth`): authorize `https://auth.x.ai/oauth2/authorize`, scope `openid profile email offline_access grok-cli:access`, loopback 56122 `/callback` 127.0.0.1, verifier 96 bytes. → **deferred** (ledgered Plan-1: devin-desktop browser-PKCE stays deferred; same ruling for grok browser-PKCE — device + paste cover workers.dev UX).
- Paste import (fallback): accepts (a) raw JWT string, (b) `{access_token, refresh_token?, id_token?, token_type?, scope?, expires_in?}`, (c) `{accessToken: <JWT or auth.json blob>}` where auth.json shape is `{ "https://auth.x.ai::<clientId>": { key: "eyJ...", refresh_token?, expires_at? } }` (prefer the key matching issuer `https://auth.x.ai` + client id; iterate others). JWT payload claims read: `email`, `sub`, `principal_type`, `principal_id`, `team_id`, `organization_id`, `tier`, `exp`. Identity resolution: principal_type team/organization (lowercased) with principal_id → userId/organizationId from principal_id; tier default 1. expiresIn resolution: `expires_in` ?? (`expires_at` parsed minus now) ?? JWT `exp` minus now ?? 21600; clamp minimum 1s (#5775). meta: `userId`, `email`, `teamId`, `tier`, `principalType`, `principalId`, `organizationId`, `autoSync: true`. label = email.
- Unified mapTokens dispatch: response carrying snake_case `access_token` (string) → browser/device shape (id_token OIDC identity: `email`/`preferred_username`/`name`, meta `scope`, `tokenType`, `autoSync: true`, expiresIn clamp ≥1 default 21600); anything else → paste-import shape above.
- Refresh: standard form grant at `https://auth.x.ai/oauth2/token` with `client_id` only → default `standardRefresh` works (grok-cli.ts comment: "refresh reads config.tokenUrl generically").

### github (`GITHUB_CONFIG`)
- Device `https://github.com/login/device/code`; token `https://github.com/login/oauth/access_token`; userinfo `https://api.github.com/user`; scope `read:user`; client id `Iv1.b507a08c87ecfe98`.
- Device/poll requests: `Content-Type: application/x-www-form-urlencoded`, `Accept: application/json`; device body `client_id`, `scope`; poll body `client_id`, `device_code`, `grant_type=urn:ietf:params:oauth:grant-type:device_code`. Read body ONCE, JSON.parse with fallback `{error:"invalid_response", error_description: text}` (Plan-1 engine already handles the shape; adapter returns `{ok, data}`).
- postExchange: GET `https://api.github.com/copilot_internal/v2/token` headers `Authorization: Bearer <access>`, `Accept: application/json`, `X-GitHub-Api-Version: 2026-08-01`, `User-Agent: GitHubCopilotChat/1.0.91`; non-2xx → null (no Copilot subscription). GET `https://api.github.com/user` same headers (non-2xx → `{}`). Version pin `GITHUB_COPILOT_CLI_VERSION = "1.0.91"` (OmniRoute auto-refreshes from npm; static pin accepted — Plan-1 ledger ruling #5).
- meta: `copilotToken` (copilotTokenData.token), `copilotTokenExpiresAt` (copilotTokenData.expires_at), `githubUserId`, `githubLogin`, `githubName`, `githubEmail`, `autoSync: true`. (OmniRoute's `copilotCapabilities` discovery is upstream-forwarding machinery — NOT ported; noted in ledger.) label = githubLogin ?? githubName.
- Refresh: standard form grant at token endpoint (`client_id` only, no secret — buildFormParams skips empty) → default `standardRefresh` works. Short-lived `copilot_internal` token is re-fetched by forwarding later, not by refresh (ledger note).

### ghe-copilot
- Everything derived from `gheUrl` (per-connection, supplied at start as `?gheUrl=` on the start URL — **manual API start per USER DECISION: `POST /admin/api/oauth/ghe-copilot/start?gheUrl=https://<ghe-host>`, no console field this wave (Plan 3); the card's instructions string documents it**; `normalizeGheUrl` = trim, strip trailing slashes, require non-empty). Endpoints: device `${gheUrl}/login/device/code`; token `${gheUrl}/login/oauth/access_token`; copilot token `${gheUrl}/api/v3/copilot_internal/v2/token`; user `${gheUrl}/api/v3/user`.
- Response field allow-listing: device fields `device_code`, `user_code`, `verification_uri`, `verification_uri_complete` (strings), `expires_in`, `interval` (numbers); token fields `access_token`, `refresh_token`, `token_type`, `scope` + `expires_in`. Error normalization: known codes `authorization_pending`, `slow_down`, `expired_token`, `access_denied`, `incorrect_device_code`, `incorrect_client_credentials`, `device_flow_disabled`, `unsupported_grant_type`; anything else → `invalid_response`; `error_description` passed through (our engine sanitizes by construction — never re-render raw HTML).
- postExchange = copilotToken + userInfo lookups (both best-effort → `{}` on failure; pass `gheUrl`, `copilotApiUrl = copilotToken.endpoints.api`, `copilotProxyUrl = copilotToken.endpoints.proxy` through extra).
- meta: `gheUrl`, `copilotApiUrl`, `copilotProxyUrl`, `copilotToken`, `copilotTokenExpiresAt`, `githubUserId`, `githubLogin`, `githubName`, `githubEmail`, `autoSync: true`.
- Refresh: `${meta.gheUrl}/login/oauth/access_token` form grant (`client_id`, `refresh_token`) — custom hook; missing gheUrl in meta → throw `no gheUrl in connection meta` (unrecoverable reconnect).

### kimi-coding (`KIMI_CODING_CONFIG`)
- Device `https://auth.kimi.com/api/oauth/device_authorization`; token `https://auth.kimi.com/api/oauth/token`; client id `17e5f671-d194-4dfb-9706-5516cb48c098`.
- Headers on BOTH device + poll: `Content-Type: application/x-www-form-urlencoded`, `Accept: application/json`, plus identity set: `X-Msh-Platform: kimi_code_cli`, `X-Msh-Version: 2.1.1`, `X-Msh-Device-Name: <name>`, `X-Msh-Device-Model: <model>`, `X-Msh-Os-Version: <os>`, `X-Msh-Device-Id: <uuid>`. Server-side values (no os/hostname on Workers): `Device-Name` = `"freeai-gateway"`, `Device-Model` = `"cloudflare-worker"`, `Os-Version` = `"workers"`, `Device-Id` = random UUID generated at connect and persisted in meta (OmniRoute persists it for exactly this reason: Kimi rotates refresh tokens per refresh; a changing device id trips the anti-bot pipeline).
- Device body: `client_id` only. Response validation: requires `device_code`, `user_code`, `verification_uri_complete` (throw "Device authorization response missing <field>"); `verification_uri` defaults ""; `expires_in` passthrough; `interval` default 5.
- Poll body: `client_id`, `device_code`, `grant_type=urn:ietf:params:oauth:grant-type:device_code`. Read body once, JSON fallback `{error:"invalid_response", error_description:text}`.
- meta: `deviceId`, `deviceName`, `deviceModel`, `osVersion`. label = none from mapTokens (upstream sends no identity) → console shows prefix.
- Refresh: custom hook (snake_case per builder-b1 contract) — token endpoint, form `grant_type=refresh_token`, `refresh_token`, `client_id`; identity headers with `deviceId` from `priorMeta` (engine passes row.meta; NEVER regenerate on refresh — RF-3); missing meta.deviceId → hook throws (reconnect required). Hook returns upstream snake_case; meta persistence flows through `mapTokens(raw, undefined, priorMeta)`. Terminal: `invalid_grant`, `invalid_request`.

### muse-code (`MUSE_CODE_CONFIG`)
- Device `https://auth.meta.com/oidc/device/authorization/` (trailing slash verbatim); token `https://auth.meta.com/oidc/device/token/` (trailing slash); mint `https://api.meta.ai/muse-code/key`; client id `1031625952748946`. NO PKCE on this grant (engine always passes a challenge — ignore it).
- All requests: POST form, `redirect: "error"`, `AbortSignal.timeout(20000)` (Workers supports `AbortSignal.timeout`), headers `Accept: application/json`, `User-Agent: muse-code/1.0.2`, `Content-Type: application/x-www-form-urlencoded`. Catch network errors → `{ok:false, status:0, data:{error:"network_error"}}`.
- Device body: `client_id`. Response normalization (`museCodeDeviceResponse.ts`): verification URLs must parse and have origin `https://auth.meta.com` with no username/password (throw "Muse Code returned an invalid authorization URL."); `expires_in` must be a finite number 0<x≤86400 (throw "Muse Code returned an invalid device code expiry."); `device_code`/`user_code` required trimmed text; `interval` finite >0 else 5.
- Poll body: `client_id`, `device_code`, `grant_type=urn:ietf:params:oauth:grant-type:device_code`. Success: `access_token` (trimmed) + optional `expires_in`, `token_type`. Error mapping: `authorization_pending`→"Authorization pending.", `slow_down`→"Authorization pending.", `access_denied`→"Authorization denied.", `expired_token`→"Device code expired.", `invalid_grant`→"Authorization failed." (error_description carries these); unknown → `{error:"invalid_response"}`. Return ok=false for invalid_response.
- postExchange: mint — POST mint URL, headers muse set + `Authorization: Bearer <dca>`, `Content-Type: application/json`, body `{"dca_token": "<dca>"}`. Response fields: `api_key`/`apiKey` (required — throw "Muse Code key mint response missing api_key."), `base_url`/`baseUrl`, `user_email`/`email`, `user_full_name`/`name`, `subs_tier_name`, `subs_tier_id`, `is_subs_active`, `has_payment_method`, `require_payment`, `can_subscribe`. Mint failure at connect = best-effort (catch → `{dcaToken}` only; a DCA-only record is still saved).
- mapTokens: `accessToken` = minted.apiKey || (isDca(access) ? "" : access) || dcaToken; `refreshToken` = dcaToken always (the durable credential); `expiresIn` = minted present ? undefined : tokens.expires_in (minted keys don't inherit DCA expiry); label = name ?? email; meta: `dcaToken`, `authKind:"oauth"`, `baseUrl`, `email`, `name`, `subsTierName`, `subsTierId`, `isSubsActive`, `hasPaymentMethod`, `requirePayment`, `canSubscribe`, `dcaExpiresAt` (ISO), `lastRefresh` (ISO).
- Refresh (custom hook, snake_case per builder-b1): remint from meta.dcaToken (or refreshToken when it starts with `dca:`). Success → `{access_token: minted.apiKey, refresh_token: dcaToken, muse_mint: {...minted fields}}` — muse `mapTokens` reads the minted payload from `extra ?? (tokens as any).muse_mint` and dca from the snake_case refresh_token, preserving priorMeta fields. 401/403 from mint → hook throws `MuseCodeMintError` (name+status; refresh.ts unrecoverable rule); other failures (429 etc.) → hook throws a plain Error (transient; stored api_key never expires; surfaces as reconnect-required ONCE per USER DECISION). Mint error carries HTTP status — wrap fetch: non-2xx → throw with status.

### minimax-code
- Region-resolved account base: `en` → `https://account.minimax.io`, `cn` → `https://account.minimax.cn` (default `en`; static — no env plumbing for now, ledger if cn needed). Device `${base}/oauth2/device/code`; token `${base}/oauth2/token`. client id `mcode-public`; scope `agent.default`; audience `agent-backend`; S256; UA `minimax-code-cli`; device grant `urn:ietf:params:oauth:grant-type:device_code`.
- **Device + S256 PKCE:** device body `client_id`, `scope`, `audience`, `code_challenge` (engine challenge), `code_challenge_method=S256`. Poll body `grant_type` (device grant), `device_code`, `client_id`, `code_verifier` (engine verifier from pending).
- POSTs: form-urlencoded, UA header, 20s timeout, `redirect:"error"`; pending answers arrive as HTTP 400 + JSON body — the BODY decides (status only separates unreachable from refused); network catch → `{error:"network_error"}`.
- Device response defaults: `expires_in` 300, `interval` 5; require `device_code`+`user_code` (throw with `error_description || error || "unknown error"`).
- Poll: access_token present → ok; else error passthrough (`error`/`error_description`); status≠0 without error → `{error:"poll_failed", error_description:"Poll failed: <status>"}`; status 0 → `{error:"network_error"}`.
- **Server-only port:** OmniRoute's postExchange writes the credential into the local CLI profile (`persistProfileCredential`) — DO NOT port that. Our postExchange: none. mapTokens stores the real tokens: accessToken/refreshToken/expiresIn straight from the device grant; label "MiniMax Code account"; meta `authKind:"oauth"`, `accountBase`.
- Refresh (custom hook): POST `${base}/oauth2/token` form `grant_type=refresh_token`, `refresh_token`, `client_id`, `scope=agent.default`, `audience=agent-backend` (no PKCE on refresh; base from meta.accountBase ?? config default).

### workbuddy
- Own host (separate product from CodeBuddy CN): stateUrl `https://www.workbuddy.ai/v2/plugin/auth/state`; tokenUrl `https://www.workbuddy.ai/v2/plugin/auth/token`; refreshUrl `https://www.workbuddy.ai/v2/plugin/auth/token/refresh`; platform `CLI`; pollInterval 5000. No client_id/secret.
- Start: POST `${stateUrl}?platform=CLI` (query AND JSON body `{platform:"CLI"}` — send both), headers `Content-Type: application/json`, `Accept: application/json`, `X-Product: SaaS`. Response `{code, data:{state, authUrl|url}, msg}`; `code !== 0` or missing state → throw `WorkBuddy state error: <msg>`. Adapter maps to DeviceCodeResponse: `device_code = state`, `user_code = state`, `verification_uri = authUrl`, `verification_uri_complete = authUrl`, `expires_in: 600`, `interval: max(1, floor(5000/1000))` = 5.
- Poll: GET `${tokenUrl}?state=<state>` headers `Accept: application/json`, `X-Product: SaaS`. `code === 0 && data.accessToken` → `{ok:true, data:{access_token, refresh_token (data.refreshToken || ""), token_type (|| "Bearer"), expires_in}}`. Otherwise `{ok:false, data:{code, msg}}` — **the engine must surface `code`/`msg` for terminal errors** (Task 2 msg/code fix; pending code = 11217). The token is ONE-SHOT: a second poll reverts to 11217 — engine stops polling immediately on success (already does).
- mapTokens: accessToken, refreshToken, `expiresIn = tokens.expires_in || 31_104_000` (long default — the gateway issues ~361-day tokens and doesn't always report expiresIn; a day-default would cause a refresh loop), meta `{}`. label = none → prefix.
- Refresh (custom hook): POST refreshUrl, headers `Content-Type: application/json`, `Accept: application/json`, `X-Refresh-Token: <refreshToken>`, `X-Product: SaaS`, `X-Domain: www.workbuddy.ai`, `User-Agent: WorkBuddy/5.5.6`, body `{}`. Success `{code:0, data:{accessToken, refreshToken?, expiresIn}}` → hook returns snake_case `{access_token, refresh_token: data.refreshToken || old, expires_in}` (mapTokens passthrough). `code !== 0` or missing accessToken → hook THROWS "WorkBuddy token refresh returned no token" (builder b10-v: never return an error-shaped object — refresh.ts has no null-contract). HTTP non-ok → throw "Failed to refresh WorkBuddy token (<status>)".

### cursor
- Config: loginUrl `https://cursor.com/loginDeepControl`; pollUrl `https://api2.cursor.sh/auth/poll`; refreshUrl `https://api2.cursor.sh/auth/exchange_user_api_key`; clientVersion pin `2026.07.08-0c04a8a` (CURSOR_AGENT_CLI_VERSION); clientType `ide`.
- Deep-control flow (ported as device mode): requestDeviceCode — generate engine-provided S256 challenge (the engine passes it), `uuid = crypto.randomUUID()`; loginUrl = `${loginUrl}?challenge=<challenge>&uuid=<uuid>&mode=login&redirectTarget=cli`; return `{device_code: uuid, user_code: uuid, verification_uri: loginUrl, verification_uri_complete: loginUrl, expires_in: 900, interval: 2}`. (OmniRoute keeps the verifier server-side in a 15-min session; ours persists in the pending row automatically.)
- Poll: GET `${pollUrl}?uuid=<device_code>&verifier=<codeVerifier>` — NO extra headers. HTTP 404 → `{ok:false, data:{error:"authorization_pending"}}`; ok → JSON `{accessToken, refreshToken}` (missing either → `{error:"Cursor auth response missing tokens"}`); other status → `{ok:false, data:{error:"Cursor auth poll failed: <status>"}}`.
- mapTokens: accessToken, refreshToken (required non-empty), expiresIn from JWT `exp` of the ACCESS token minus 5-min skew (`(exp*1000 - now - 300000)/1000`; undecodable → 3600); email = lowercase JWT `email` (string); accountId = JWT `sub`; meta `authMethod: "deep_control"`. label = email ?? accountId.
- Paste import (secondary): input.token = accessToken from Cursor IDE state.vscdb (`cursorAuth/accessToken`) or cursor-agent CLI. Validate: string, length ≥ 50 ("Invalid token format. Token appears too short."); optional `machineId` (authMethod "imported", else "cursor-agent"); NO API validation (protobuf API — validated on use). Optional paste payload `{accessToken, refreshToken?, expiresIn?, machineId?, authMethod?}` → same fields. JWT exp drives expiresIn (fallback 86400). meta `machineId` (null when absent), `authMethod`.
- Refresh (custom hook): POST refreshUrl, headers `Authorization: Bearer <refreshToken>`, `Content-Type: application/json`, body `{}`. 15s timeout. Success `{accessToken, refreshToken?}` → hook returns snake_case `{access_token, refresh_token: data.refreshToken || old}`; expiresIn from new access JWT exp minus skew (fallback 3600, via mapTokens). 401/403 → hook throws with name `CursorRefreshUnauthorized` (unrecoverable rule in refresh.ts); 429/500/502/503/504 → retryable: up to 3 attempts, backoff `300ms * 2^attempt * (0.8..1.2 jitter)` (implement inside the hook; adapter tests stub fetch with 503×2 then 200 and assert 3 fetches); all 3 fail → throw "Cursor token refresh failed after 3 attempts (last status <s>)" — provider-specific last_error (USER DECISION: accept + verbatim text).

### openference (`OPENFERENCE_CONFIG`)
- authorize `https://openference.com/app/oauth/authorize`; token `https://openference.com/oauth/token`; userinfo `https://openference.com/oauth/userinfo`; scope `openid profile email model:invoke offline_access`; S256; loopback 56123 `/callback` 127.0.0.1 (dead on workers.dev → paste-code; adapter `redirectUri = "http://127.0.0.1:56123/callback"` constant).
- buildAuthUrl: `response_type=code`, `client_id`, `redirect_uri`, `scope`, `code_challenge`, `code_challenge_method=S256`, `state` (URLSearchParams.toString()).
- Exchange body: standard 5 fields. postExchange: GET userinfo with `Authorization: Bearer <access>`, `Accept: application/json`; non-2xx → `{}` (best-effort).
- mapTokens: id_token identity (`email`/`preferred_username`, `name`) preferred; userinfo fallback email candidates `email`, `preferred_username`; name candidates `name`, `email`, `preferred_username`; meta `scope` (|| config scope), `tokenType` (|| "Bearer"). label = name || email.
- Refresh: standard form grant client_id only (rotating one-time-use `oar_*` refresh tokens; keep old when response omits). Default `standardRefresh` works. Terminal: `invalid_grant`, `token_expired`, `invalid_token`, 401.

### clinepass (alias of cline)
- Same WorkOS flow as `cline` (already ported in Plan 1): authorize `https://api.cline.bot/api/v1/auth/authorize` with `client_type=extension`, `callback_url`, `redirect_uri`; token-exchange JSON POST `https://api.cline.bot/api/v1/auth/token` `{grant_type:"authorization_code", code, client_type:"extension", redirect_uri}` (data-envelope fields `data.accessToken`/`accessToken` etc.).
- Refresh: POST `https://api.cline.bot/api/v1/auth/refresh`, headers JSON, body `{refreshToken, grantType: "refresh_token", clientType: "extension"}`; response envelope `data || payload`; `expiresAt` ISO → expiresIn = max(1, floor((t - now)/1000)); rotate-in `data.refreshToken || old`. Terminal: `invalid_grant`, `invalid_request` (embedded codes like "failed to refresh token: invalid_grant" match via substring — our hook checks parsed `error` string contains a terminal code).
- codebuddy (both cn + intl) refresh: POST `${config.refreshUrl}` (`https://copilot.tencent.com/v2/plugin/auth/token/refresh` / `https://www.codebuddy.ai/v2/plugin/auth/token/refresh`), headers `{ "Content-Type": "application/json", "Accept": "application/json", "User-Agent": <pinned UA>, "X-Requested-With": "XMLHttpRequest", "X-Domain": <pinned domain>, "X-Refresh-Token": <refreshToken>, "X-Auth-Refresh-Source": "plugin", "X-Product": "SaaS" }` (OmniRoute `codebuddyShared.ts` verbatim; CN UA `CLI/2.108.1 CodeBuddy/2.108.1` domain `copilot.tencent.com`, INTL UA `IDE/2.108.1 CodeBuddy/2.108.1` domain `www.codebuddy.ai`), body `{}`. Success `{code:0, data:{accessToken, refreshToken?, expiresIn}}` → snake_case return; `code !== 0`/missing accessToken → throw "CodeBuddy token refresh returned no token"; HTTP non-ok → throw "Failed to refresh CodeBuddy token (<status>)" (same throw ruling as workbuddy, builder b10-v).

---

## Task 1 — Engine extensions + encrypted pending state

**Files:** `src/oauth/types.ts`, `src/oauth/engine.ts`, `src/oauth/refresh.ts`, `src/oauth/store.ts`, `src/oauth/crypto.ts`, `migrations/0004_oauth_pending_extra.sql`, `test/oauth-engine-extensions.test.ts` (new), `test/oauth-pending-encryption.test.ts` (new), **plus touch-ups in three Plan-1 test files whose assumptions change (builder b5): `test/oauth-engine.test.ts` (state/verifier plaintext assertions → decrypted assertions; base64 alphabet note — the `code_verifier` regex test must accept `+`/`/`/`=` or compare the decrypted value; `INSERT` destructure gains the new `extra` bind param), `test/oauth-store.test.ts` and `test/admin-oauth.test.ts` (same INSERT destructure fix).**

**Interfaces (exact):**
```ts
// types.ts — OAuthAdapter gains (all optional unless noted):
parseStartParams?(requestUrl: URL): Record<string, unknown> | undefined;
requestDeviceCode?(config, codeChallenge?: string, startParams?: Record<string, unknown>): Promise<DeviceCodeResponse>;
pollToken?(config, deviceCode: string, codeVerifier?: string, startParams?: Record<string, unknown>): Promise<PollResult>;
postExchange?(tokens: RawTokens, startParams?: Record<string, unknown>): Promise<unknown>;
mapTokens(tokens: RawTokens, extra?: unknown, priorMeta?: Record<string, unknown>): MappedTokens;
refresh?(config, refreshToken: string, meta?: Record<string, unknown>): Promise<RawTokens>;
  /** PKCE verifier byte size override (default 32); xai needs 96. */
  pkceVerifierBytes?: number;

// DeviceCodeResponse gains ONE optional field (kimi Task 6 needs it):
export interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
  /** Adapter-chosen value threaded into pending extras (e.g. kimi deviceId). */
  device_id?: string;
}
```
- `store.savePending` gains `extra?: Record<string, unknown>` and `PendingRow` gains `extra?: Record<string, unknown> | null`. ALL sensitive pending columns (state, codeVerifier, device_code, extra) stored encrypted.
- Pending encryption codec in `store.ts`: plaintext → `enc:v1:` + base64(iv‖ciphertext) (reuse `encryptToken`/`decryptToken` with base64 wrapping — store keeps the CryptoKey local). Read path: value starts with `enc:v1:` → decrypt (failure → treat field as null, never throw); otherwise return as-is (Plan-1 rows stay readable; new writes always encrypted).
- `migrations/0004_oauth_pending_extra.sql`: `ALTER TABLE oauth_pending ADD COLUMN extra TEXT;`
- **`savePending` upsert must also update `extra` in the `ON CONFLICT` clause** (else a stale gheUrl/deviceId survives into the next flow).
- **Device pending TTL clamp (builder b8):** engine device branch uses `ttlSec = Math.min(Math.max(d.expires_in || 900, 60), 1800)` instead of the hard-coded 900 — grok-cli reports 1800, muse allows up to 86400.
- **`postExchange` runs ONLY on paste-code exchange success and device-poll success — never on the paste/importToken path** (claude setup-token import must not trigger the bootstrap call; Plan-1 paste behavior preserved).
- **Refresh-hook contract (builder b1):** custom `refresh` hooks return UPSTREAM snake_case (`{access_token, refresh_token?, expires_in?/expires_at?}`) — never camelCase mapped shapes. Meta that must persist across refresh comes from `mapTokens(raw, undefined, priorMeta)` (each adapter resolves identity/meta from `priorMeta` when `extra` is absent — RF-3 generalized).

**Steps:**
- [ ] **RED** — `test/oauth-engine-extensions.test.ts`: (a) device start with an adapter exposing `parseStartParams` → engine passes its result as 3rd arg to `requestDeviceCode`, and a subsequent `poll` passes the same object as 4th arg to `pollToken`; (b) engine passes a fresh S256 `codeChallenge` as 2nd arg to `requestDeviceCode` and `pending.codeVerifier` as 3rd arg to `pollToken` (same value both ways — RF-4); (c) adapter `postExchange` result reaches `mapTokens` as 2nd arg on device success and on paste-code complete; **(c2) builder b2: the device `poll()` success path threads `pending.extra` into `finalizeAndSave` → `mapTokens` receives it as `extra` (kimi deviceId, ghe gheUrl depend on this)**; (d) refresh path calls `mapTokens(raw, undefined, row.meta)` and `adapter.refresh(config, refreshToken, row.meta)` (spy via a Plan-1-style D1 stub); (e) `DeviceCodeResponse.device_id` threading: adapter returns `{...d, device_id: "dev-1"}` → pending extras carry `{deviceId: "dev-1"}` (key renamed to camelCase `deviceId`) merged after startParams; (e2) device TTL clamp: adapter returning `expires_in: 1800` → pending row lives 1800s; `expires_in: 0/undefined` → 900; (f) Plan-1 adapter regression: trae/kilocode adapters still map with 0/1-arg calls (existing tests already cover — run them).
- [ ] **RED** — `test/oauth-pending-encryption.test.ts`: savePending with state/codeVerifier/deviceCode/extra → raw D1 stub row contains NO plaintext verifier/challenge/gheUrl (assert row text lacks the seeded values, contains `enc:v1:`); getPending returns decrypted originals; a row with a corrupt `enc:v1:` payload reads that field as null without throwing.
- [ ] **GREEN** — implement signatures + threading: `start()` device branch generates pkce ALWAYS (challenge → requestDeviceCode, verifier → pending), calls `parseStartParams` when present, saves encrypted pending with extras `{...(startParams ?? {}), ...(d.device_id ? { deviceId: d.device_id } : {})}`; `poll()` passes `(config, deviceCode, pending.codeVerifier ?? undefined, pending.extra ?? undefined)`; `finalizeAndSave(env, a, tokens, authKind, opts?: {startParams?, priorMeta?})` calls `postExchange(normalized, startParams)` then `mapTokens(normalized, extra, priorMeta)`; `complete()` paste-code branch threads no startParams; `refresh.ts` passes meta.
- [ ] **GREEN** — store codec + migration file. Engine's `handleOauthList`/status responses unaffected (pending internals never leave the store).
- [ ] **Commit:** `oauth: postExchange/mapTokens-extra/priorMeta/verifier threading + encrypted pending extras`

## Task 2 — Engine/console carry-overs (review minors + recommendations)

**Files:** `src/oauth/errors.ts` (new — builder b7: `store.ts` must not import `forward.ts`, that would cycle `forward → oauth/refresh → oauth/store`), `src/admin/oauth.ts`, `src/index.ts`, `src/oauth/engine.ts` (redirect resolution), `public/admin/app.js`, `test/oauth-carryovers.test.ts` (new).

**Interfaces:**
- `export class MissingKeyMaterialError extends Error {}` in `src/oauth/errors.ts`; `store.requireKey` throws it (same message "set OAUTH_ENCRYPTION_KEY secret first"); `oauthGuard` checks `instanceof` first (keep the message-regex as a second safety net for engine-wrapped strings).
- Auto-callback (**USER DECISION 2026-11-16: state-matched PUBLIC callback** — the admin cookie is SameSite=Strict, so a redirect arriving from the provider carries no cookie; admin-gating would 401 in production): GET `/admin/oauth/:prefix/callback?code=<code>&state=<state>` registers in `src/index.ts` BEFORE the admin-gated API routes and the `/admin` assets catch-all (`wrangler.jsonc` `run_worker_first: ["/admin","/admin/*"]` already routes `/admin/*` to the worker — no config change), with NO checkAdmin. Handler gate: `getPending(prefix)` → require row exists, `row.mode === "pkce"`, not expired (`row.expiresAt > now`), and decrypted `row.state` strictly equals the query `state`. On mismatch/missing/expired → 400 HTML page `<title>FreeAI Gateway</title><p>Invalid or expired login link. Start the login again from the admin console.</p>`. On match: run `complete(env, prefix, {code}, new URL(request.url))` (complete itself consumes the pending verifier and deletes the row on success), then ALWAYS `deletePending(prefix)` in a finally — a failed exchange consumes the state too (single-use); the user restarts from the console. Responses: success → 200 HTML `<p>Connected <provider>. You can close this tab.</p>`; complete failure → 200 HTML page with the error message. The admin-gated manual `complete` (POST /admin/api/oauth/:prefix/complete) stays unchanged for paste flows. No token material in any page.
- **Redirect resolution change (builder b3):** `resolveRedirectUri()` for adapters WITHOUT a static `redirectUri` now returns `{origin}/admin/oauth/${prefix}/callback` instead of `{origin}/admin` — the auto-callback route is then actually reachable (codex is the only affected adapter this plan; assert start/exchange use the IDENTICAL string).
- Poll-chain liveness (app.js, builder b9): module-level `const oauthPollGeneration = {}` keyed by prefix; `startDevicePoll` increments, captures, clears any prior timer first; every scheduled callback aborts silently if `gen !== oauthPollGeneration[prefix]`. **The disconnect handler and the complete handler must call `stopOauthPoll(prefix)`** (today they only delete `state.oauthFlows` — that's the actual bug the RED test exposes).
- slow_down backoff (app.js): poll result `error === "slow_down"` → next delay = current interval + 5000; keep the bumped interval in a module-level map next to `oauthPollGeneration` — NOT in `state.oauthFlows` (that object is re-rendered every poll).
- Terminal poll error surfacing (engine): when a device poll returns `ok:false` without a known non-terminal error AND `data.code` (number) or `data.msg` (string) exist, the engine's error string becomes `` `poll failed (code <code>): <msg>` `` — codebuddy/workbuddy shape. Keep `error`/`error_description` priority as-is.
- **Console paste-token box (USER DECISION 2026-11-16: add it):** `listAdapters` response (`src/admin/oauth.ts`) gains `importToken: boolean` per adapter (true when the adapter exposes `importToken`); `renderOauth` (app.js) renders a second textarea (`placeholder "Or paste a token (setup token / auth.json)"`) + submit button on device/paste-code cards where `p.importToken`, posting `{token}` to the same complete endpoint the code box uses (paste-mode cards keep the existing single box; cards without importToken get no box). **Engine-side routing of `{token}` (input.token → paste path) lands in Task 10** — until then box submits error on real adapters; Task-2 tests spy the POST body only.

**Steps:**
- [ ] **RED** — typed error: store missing-key → oauthGuard returns 503 via instanceof (test: stub importAesKey null → POST /admin/api/oauth/x/status → 503 and message unchanged).
- [ ] **RED** — auto-callback GET route (PUBLIC — no admin cookie supplied): seed a pending row via `savePending` (`mode:"pkce"`, `state:"st-1"`, verifier) → `GET /admin/oauth/<prefix>/callback?code=abc&state=st-1` → 200 text/html containing the provider name; `complete` spy received `code:"abc"`; pending row consumed (`getPending` → null). Mismatched state (`?state=wrong`) → 400 HTML; missing state param → 400; expired row (`expiresAt < now`) → 400; unknown prefix → 400; device-mode pending row with a matching state → 400 (route serves pkce only). Single-use on failure: stub `exchangeToken` throws → row still deleted → replaying the same state+code → 400. Plus the redirect-resolution test: a paste-code adapter with NO static redirectUri → start's buildAuthUrl received `{origin}/admin/oauth/<prefix>/callback` and the SAME string reached `exchangeToken` (builder b3). Admin-gated API routes keep their 401 JSON behavior (existing Plan-1 tests cover — run them).
- [ ] **RED** — liveness: DOM test — start device poll for `x`, immediately disconnect (which now calls `stopOauthPoll`), flush timers → engine poll called exactly once (no re-arm); double startDevicePoll → first chain's timer cleared (poll count bounded).
- [ ] **RED** — slow_down: fake-timer DOM test — first poll answers `{ok:false,data:{error:"slow_down"}}` → next scheduled delay ≥ interval+5000.
- [ ] **RED** — paste-token box: register a test adapter (`registerAdapter` with `prefix:"box-test"`, `flowMode:"device"`, an `importToken` fn) → `/admin/api/oauth` list response carries `importToken:true` for it and `false` for Plan-1 device adapters (e.g. kilocode); DOM test — the box-test card renders the token textarea, and its submit POSTs `{token:"t-1"}` (fetch spy on body); the cline card does NOT render the box; the trae paste card keeps its existing single box.
- [ ] **RED** — msg/code: pollToken returns `{ok:false, data:{code:11217}}`… careful: 11217 is workbuddy PENDING — engine must NOT treat unknown `code` as terminal unless the adapter says the flow ended. Rule: NON_TERMINAL stays `authorization_pending`/`slow_down` only; workbuddy adapter maps `code===11217` → `{ok:false, data:{error:"authorization_pending"}}` in ITS pollToken (adapter-level, Task 9); the ENGINE's msg/code rule applies only when `data.msg` is a string (message-only shape): error string `poll failed: <msg>` (+ `code <code>` when numeric). Test with a fake adapter returning `{ok:false, data:{code:500, msg:"boom"}}` → error text contains both; `{ok:false,data:{error:"expired_token"}}` unchanged.
- [ ] **GREEN** — implement all six; also fold `#5` fallback tag now? **No** — `missing-token:<prefix>` rename lands with forwarding (ledger note stays).
- [ ] **Commit:** `oauth: carry-overs — typed missing-key error, public state-matched callback, console paste-token box, poll liveness + slow_down backoff, msg/code surfacing`

## Task 3 — Adapter/store carry-overs

**Files:** `src/oauth/providers/kilocode.ts`, `src/admin/providers.ts`, `test/oauth-carryovers-store.test.ts` (new; may reuse Task-2 file).

**Steps:**
- [ ] **RED** — kilocode envelope: device start response `200` with `{data:{code:""}}` (or missing fields) → engine start throws 502 with a message naming the missing field (mirror freebuff's validation: require non-empty `data.code`, `data.link`; reuse Plan-1 freebuff pattern).
- [ ] **RED** — `handleTestProvider` oauth branch (builder b4): `src/providers.ts` PROVIDERS has no `oauth:true` rows and no injection point — so keep the `list()` lookup for API-key rows, then FALL BACK to `getAdapter(prefix)` (`src/oauth/engine.ts`) + `getTokenStatus`: connected oauth adapter → `{ok:true, provider:"<prefix>", auth:"oauth"}` (no `missing-key:undefined`); not connected → `{ok:false, reason:"not_connected"}`. Test uses an existing adapter (`cline`) — no `providers.ts` change. (Putting the 13 into `/admin/api/providers` is Plan-3 forwarding scope.)
- [ ] **RED** — D1 miniflare test (carry-over: "D1-level miniflare test (0001–0003, one save/get cycle)"; placement per builder b6): add dev dep `@cloudflare/vitest-pool-workers` (workd already allowScripts-approved; **first verify it accepts the repo's pinned vitest ^5.1.0 — check its peer range on npm before installing**), test file at **`test-miniflare/d1.test.ts`** (OUTSIDE the default vitest include `**/*.test.ts` — there is no vitest.config.ts today, so `test/miniflare/` would be collected by the main plain-vitest run and `import "cloudflare:test"` would also break `tsconfig.json`'s `test/**` typecheck) + `vitest.miniflare.config.ts` with `include: ["../test-miniflare/**/*.test.ts"]` wired to `wrangler.jsonc`'s D1 binding and migrations 0001–0004; **add the `test-miniflare/` dir to tsconfig exclude**. Two assertions: (a) one `saveToken` → raw `SELECT access_token` is not plaintext + `getToken` round-trips; (b) one `savePending` (state + codeVerifier + deviceCode + extra) → raw row has no plaintext and `getPending` round-trips. `package.json` gains `"test:miniflare": "vitest run -c vitest.miniflare.config.ts"`; the MAIN suite never imports miniflare. If workerd or the peer-range check fails, fall back to the SQL-recorder assertion (exact ON CONFLICT SQL + `enc:v1:` prefix on every sensitive column) and record the downgrade in the ledger.
- [ ] **GREEN** + **Commit:** `oauth: kilocode envelope validation, handleTestProvider oauth branch, miniflare D1 test`

## Task 4 — github adapter

**Files:** `src/oauth/providers/github.ts` (new), `src/oauth/providers/registry.ts`, `test/oauth-github.test.ts` (new).

**Interfaces:** adapter `prefix: "github"`, `flowMode: "device"`, config `{ clientId, deviceCodeUrl, tokenUrl, userInfoUrl, scopes, apiVersion, copilotTokenUrl, userAgent }` (values from recon block; `userAgent: "GitHubCopilotChat/1.0.91"`).

**Steps:**
- [ ] **RED** — device start: fetch stub asserts URL/method/headers (`Accept: application/json`, form Content-Type) + body `client_id=Iv1.b507a08c87ecfe98&scope=read:user`; response `{device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval}` passes through to StartResult. Non-ok → 502 with upstream text.
- [ ] **RED** — poll: body has `grant_type=urn:ietf:params:oauth:grant-type:device_code`; JSON-parse-fallback shape (`text` body → `{error:"invalid_response"}`); pending `{error:"authorization_pending"}` → engine keeps polling.
- [ ] **RED** — postExchange: success → copilot fetch asserted (URL `https://api.github.com/copilot_internal/v2/token`, headers include `X-GitHub-Api-Version: 2026-08-01`, `User-Agent: GitHubCopilotChat/1.0.91`) + userinfo fetch; extra fields reach meta (`copilotToken`, `copilotTokenExpiresAt`, `githubUserId`, `githubLogin`, `githubName`, `githubEmail`, `autoSync:true`); copilot non-2xx → meta lacks copilotToken, connect still succeeds; label = `githubLogin`.
- [ ] **RED** — refresh: no custom hook → engine `standardRefresh` used against `config.tokenUrl` (assert form body client_id + refresh_token, no client_secret).
- [ ] **GREEN** + **Commit:** `oauth: github device adapter (+copilot token postExchange)`

## Task 5 — ghe-copilot adapter

**Files:** `src/oauth/providers/ghe-copilot.ts` (new), `registry.ts`, `test/oauth-ghe-copilot.test.ts` (new).

**Interfaces:** `prefix: "ghe-copilot"`, `flowMode: "device"`, `parseStartParams(url)` → `{ gheUrl }` when `url.searchParams.get("gheUrl")` is a non-empty `https://` URL (trim, strip trailing slashes; non-https or empty → `undefined` → adapter throws "gheUrl is required for GHE Copilot OAuth" from `requestDeviceCode` → 502). Config: `{ clientId, scopes: "read:user", apiVersion: "2026-08-01", userAgent: "GitHubCopilotChat/1.0.91" }` (endpoints NOT in config — derived). **gheUrl supply (USER DECISION 2026-11-16: manual API + instructions this wave, per-card input deferred to Plan 3):** the adapter's `instructions` string documents the manual start — "GitHub Enterprise Server only. Start via API: `POST /admin/api/oauth/ghe-copilot/start?gheUrl=https://<ghe-host>` (admin auth). github.com Copilot uses the github card, not this one." — so the card explains its own error instead of dead-ending.

**Steps:**
- [ ] **RED** — device start derives `${gheUrl}/login/device/code`; field allow-list drops unknown fields from the upstream response (stub returns an extra `foo` field → StartResult carries none); non-ok → 502 `Device code request failed (HTTP <status>)`; missing gheUrl → 502 "gheUrl is required for GHE Copilot OAuth" and the adapter `instructions` string contains the manual-start API line (assert in the list-render passthrough).
- [ ] **RED** — poll: derives token endpoint from the SAME gheUrl threaded through pending extras (RF-1: gheUrl encrypted at rest — assert raw row lacks it); error normalization: unknown upstream error → `invalid_response`; known codes pass; `error_description` flows into the engine error.
- [ ] **RED** — postExchange: copilot `${gheUrl}/api/v3/copilot_internal/v2/token` + user `${gheUrl}/api/v3/user` best-effort; meta pins `gheUrl`, `copilotApiUrl` (endpoints.api), `copilotProxyUrl` (endpoints.proxy), user fields.
- [ ] **RED** — refresh: custom hook uses `meta.gheUrl` (assert URL) and returns snake_case; `mapTokens` on refresh resolves `gheUrl`/`copilotApiUrl`/`copilotProxyUrl` from `priorMeta` when `extra` is absent (RF-3 rule); missing meta.gheUrl → hook throws (→ TokenExpiredError after markTokenError).
- [ ] **GREEN** + **Commit:** `oauth: ghe-copilot device adapter (per-connection gheUrl)`

## Task 6 — kimi-coding adapter

**Files:** `src/oauth/providers/kimi-coding.ts` (new), `registry.ts`, `test/oauth-kimi.test.ts` (new).

**Interfaces:** `prefix: "kimi-coding"`, `flowMode: "device"`; module helper `kimiIdentityHeaders(meta?)` → `{ "X-Msh-Platform": "kimi_code_cli", "X-Msh-Version": "2.1.1", "X-Msh-Device-Name": "freeai-gateway", "X-Msh-Device-Model": "cloudflare-worker", "X-Msh-Os-Version": "workers", "X-Msh-Device-Id": deviceId }`; `deviceId(meta?)` = `meta?.deviceId` (string, non-empty) else `crypto.randomUUID()`.

**Steps:**
- [ ] **RED** — device start: URL + form body `client_id` only; headers carry all six X-Msh-* values; missing-field validation (device_code/user_code/verification_uri_complete → 502 "Device authorization response missing <field>"); `verification_uri` defaults ""; `interval` default 5.
- [ ] **RED** — mapTokens: meta persists `deviceId/deviceName/deviceModel/osVersion` — assert the SAME deviceId that went out on the start headers is saved. Design (decided): `requestDeviceCode` generates the deviceId and returns it inside the DeviceCodeResponse as the optional `device_id` field; Task 1's engine device branch already merges it into pending extras as `{deviceId}` (RF: extra threading), and `poll()` threads pending.extra into mapTokens — so the mapTokens meta closure uses `extra.deviceId ?? crypto.randomUUID()`. Assert: start-headers deviceId === saved meta.deviceId.
- [ ] **RED** — poll + refresh use meta.deviceId: refresh hook returns snake_case and reads identity from `priorMeta` (engine passes row.meta) — **never regenerate on refresh** (RF-3: `deviceId = priorMeta?.deviceId ?? fresh()` only at connect); `invalid_grant`/`invalid_request` terminal; missing meta.deviceId on refresh → hook throws → reconnect required.
- [ ] **GREEN** + **Commit:** `oauth: kimi-coding device adapter (X-Msh identity, stable deviceId)`

## Task 7 — muse-code adapter

**Files:** `src/oauth/providers/muse-code.ts` (new), `registry.ts`, `test/oauth-muse.test.ts` (new).

**Interfaces:** `prefix: "muse-code"`, `flowMode: "device"`; helper `museHeaders(extra)` → `{ Accept: "application/json", "User-Agent": "muse-code/1.0.2", ...extra }`; `isDcaToken(t)` = startsWith `"dca:"`.

**Steps:**
- [ ] **RED** — device start: URL with trailing slashes verbatim; form body `client_id` only; invalid verification URL origin (stub `https://evil.com/...`) → 502 "Muse Code returned an invalid authorization URL."; `expires_in: 999999` → 502 "Muse Code returned an invalid device code expiry."; defaults interval 5.
- [ ] **RED** — poll: grant body 3 fields; error mapping table (authorization_pending/slow_down → pending per engine; access_denied/expired_token/invalid_grant → terminal with the mapped descriptions); unknown error → `invalid_response` (ok:false).
- [ ] **RED** — postExchange mint: body `{"dca_token": ...}`, mint URL, muse headers + Bearer; success extra `{minted:{apiKey,...}, dcaToken}`; mint failure → extra `{dcaToken}` only and connect STILL succeeds (DCA-only record); missing access_token → connect fails "Muse Code device flow completed without an access token."
- [ ] **RED** — mapTokens: accessToken = minted.apiKey || (isDca(access) ? "" : access) || dcaToken; refreshToken always dcaToken; expiresIn undefined when minted, tokens.expires_in otherwise; label name ?? email; meta field list per recon (assert `dcaExpiresAt` ISO + `lastRefresh` ISO).
- [ ] **RED** — refresh hook (snake_case contract, builder b1): remint → hook returns `{access_token: minted.apiKey, refresh_token: dcaToken, muse_mint: {...minted fields}}`; muse `mapTokens` reads `extra ?? (tokens as any).muse_mint` for the minted payload and dca from `isDca(tokens.refresh_token) ? tokens.refresh_token : priorMeta?.dcaToken` (meta merge preserved via priorMeta). Mint 401/403 → hook throws an `Error` with `.name === "MuseCodeMintError"` + `.status`; refresh.ts gains ONE adapter-agnostic rule: `err.name === "MuseCodeMintError" && (err.status === 401 || err.status === 403)` → unrecoverable. Other failures (429 etc.) → hook throws plain Error → refresh.ts marks last_error + TokenExpiredError (transient failure surfaces as reconnect-required ONCE — ruled acceptable, see carry-over #4). Assert: 429 → last_error set, row tokens unchanged; 401 → same + last_error text differs ("Muse Code key mint failed (HTTP 401).").
- [ ] **GREEN** + **Commit:** `oauth: muse-code device adapter (dca + mint postExchange, remint refresh)`

## Task 8 — minimax-code adapter

**Files:** `src/oauth/providers/minimax-code.ts` (new), `registry.ts`, `test/oauth-minimax.test.ts` (new).

**Interfaces:** `prefix: "minimax-code"`, `flowMode: "device"`; config `{ clientId: "mcode-public", scope: "agent.default", audience: "agent-backend", accountBase: "https://account.minimax.io", deviceCodeUrl, tokenUrl, userAgent: "minimax-code-cli" }`.

**Steps:**
- [ ] **RED** — device start with PKCE (RF-4): form body carries `client_id`, `scope=agent.default`, `audience=agent-backend`, `code_challenge=<engine challenge>`, `code_challenge_method=S256`; UA header set; defaults expires_in 300 / interval 5; endpoint unreachable (status 0 via thrown TypeError caught → data.error network_error) → 502 "MiniMax Code device authorization failed: the account endpoint is unreachable".
- [ ] **RED** — poll: body carries `grant_type`, `device_code`, `client_id`, `code_verifier=<pending verifier>`; HTTP 400 + `{"error":"authorization_pending"}` → engine pending; `expired_token`/`access_denied` → terminal; no-error non-ok → `poll_failed: Poll failed: <status>`.
- [ ] **RED** — mapTokens stores real tokens (accessToken/refreshToken/expiresIn passthrough; label "MiniMax Code account"; meta `authKind:"oauth"`, `accountBase`) — no postExchange, no local-profile write.
- [ ] **RED** — refresh hook (snake_case, builder b1): `${meta.accountBase ?? config.accountBase}/oauth2/token` form `grant_type=refresh_token, refresh_token, client_id, scope=agent.default, audience=agent-backend` (no PKCE on refresh); response snake_case → default mapTokens path handles it.
- [ ] **GREEN** + **Commit:** `oauth: minimax-code device adapter (S256 PKCE on device grant)`

## Task 9 — workbuddy adapter

**Files:** `src/oauth/providers/workbuddy.ts` (new), `registry.ts`, `test/oauth-workbuddy.test.ts` (new).

**Steps:**
- [ ] **RED** — start: POST to stateUrl with `?platform=CLI` query AND JSON body; `X-Product: SaaS` header; `code !== 0` → 502 "WorkBuddy state error: <msg>"; success maps state→device_code, authUrl→verification_uri (both), expires_in 600, interval 5.
- [ ] **RED** — poll: GET `${tokenUrl}?state=...`; `code===0 && data.accessToken` → ok tokens (refresh_token "" default, token_type Bearer default); `code===11217` → `{ok:false, data:{error:"authorization_pending"}}` (engine keeps polling — RF msg/code rule NOT triggered); other `{code,msg}` → terminal, engine error contains code+msg.
- [ ] **RED** — mapTokens: expiresIn default `31_104_000`; meta `{}`.
- [ ] **RED** — refresh hook (builder b1 + b10-v): returns snake_case `{access_token: data.data.accessToken, refresh_token: data.data.refreshToken || old, expires_in: data.data.expiresIn}` (mapTokens passthrough handles it); `code!==0`/missing accessToken → hook THROWS "WorkBuddy token refresh returned no token" (never returns an error-shaped object — refresh.ts has no null-contract). Assert header set + body `{}`.
- [ ] **GREEN** + **Commit:** `oauth: workbuddy plugin-auth adapter (state/poll/one-shot token)`

## Task 10 — claude adapter (paste-code + setup-token paste)

**Files:** `src/oauth/providers/claude.ts` (new), `src/oauth/engine.ts` (one rule added here), `registry.ts`, `test/oauth-claude.test.ts` (new).

**Engine rule (this task):** `complete()` for a paste-code OR device adapter accepts `input.token` when the adapter exposes `importToken` — routes through the paste path (`finalizeAndSave(env, a, tokens, "paste")`). Without `input.token`, behavior unchanged (Plan-1 tests keep passing).

**Interfaces:** `prefix: "claude"`, `flowMode: "paste-code"`, `redirectUri: "https://platform.claude.com/oauth/code/callback"`; config `{ clientId, authorizeUrl, tokenUrl, redirectUri, scopes, bootstrapUrl, bootstrapUserAgent: "claude-cli/2.1.7 (external, cli)", beta: "oauth-2025-04-20", setupTokenPrefix: "sk-ant-oat", validationModel: "claude-haiku-4-5-20251001" }`. Instructions string tells the user: open the auth URL, sign in, copy the code from the callback URL (may look like `#state` suffix), paste it here; or paste a setup token (`sk-ant-oat…`).

**Steps:**
- [ ] **RED** — buildAuthUrl: params EXACTLY `response_type=code, client_id, redirect_uri=<constant>, scope=<5 scopes joined>, code_challenge, code_challenge_method=S256, code=true, prompt=login, state` (assert `code=true` + `prompt=login` present).
- [ ] **RED** — exchangeToken: body 5 standard fields (no extras); `code#state` split handled in `complete` path? Put the split in the adapter's `exchangeToken` (input code may carry `#...` → strip). Test passes `"abc#xyz"` → exchange body code = "abc".
- [ ] **RED** — postExchange bootstrap: GET bootstrap with 4 headers; success → extra `{account_uuid, email, organizationName, organizationRole}`; non-2xx/timeout → extra null-ish `{}` and connect proceeds; label = email ?? account_uuid.
- [ ] **RED** — mapTokens + cliUserID (RF-3): connect (no priorMeta) → meta.cliUserID = 64-char hex; refresh (priorMeta `{cliUserID:"old"}`) → preserved "old". Meta also carries account fields when present.
- [ ] **RED** — setup-token paste: `complete {token: "sk-ant-oat..."}` on paste-code adapter → importToken validates prefix (reject 400 "paste a setup token starting with sk-ant-oat" for wrong prefix) → live validation POST (model claude-haiku-4-5-20251001, max_tokens 1) → 401 → 400 "Invalid OAuth token"; 500 → 400 "Provider unavailable (500)"; 200 → saved with authKind "paste", **NO postExchange call on the paste path** (builder b10-iii — assert bootstrap NOT fetched), meta `tokenKind: "setup"`; NO refresh for setup tokens — custom `refresh(config, refreshToken, meta)` hook: `meta.tokenKind === "setup"` → throw "no refresh grant for setup tokens" (→ reconnect required); else standard refresh WITH the beta header (`anthropic-beta: oauth-2025-04-20`), returning snake_case (mapTokens + priorMeta handle cliUserID). Assert both refresh branches.
- [ ] **RED** — engine rule: paste-code/device adapter + `input.token` + `importToken` → paste path (authKind "paste"); row saved; wrong `input.code` with no token → 410/400 as before (Plan-1 tests keep passing).
- [ ] **GREEN** + **Commit:** `oauth: claude adapter (paste-code + setup-token import, bootstrap, cliUserID)`

## Task 11 — codex adapter

**Files:** `src/oauth/providers/codex.ts` (new), `src/oauth/providers/jwt.ts` (NEW shared helper — base64url JWT payload decode with padding repair, used by codex/xai/grok/cursor/openference; web-standard: `atob` + TextDecoder), `registry.ts`, `test/oauth-codex.test.ts` (new).

**Interfaces:** `prefix: "codex"`, `flowMode: "paste-code"`, NO redirectUri override (after Task 2's builder-b3 change the engine resolves `{origin}/admin/oauth/codex/callback` — the only adapter whose redirect actually lands back on the gateway; the Task-2 callback route completes it in-browser). `jwt.ts`: `export function decodeJwtPayload(token: string): Record<string, unknown> | null` (3 parts, pad to %4==0, URL-safe→standard, atob, UTF-8 decode, JSON parse; null on any failure).

**Steps:**
- [ ] **RED** — buildAuthUrl: `response_type=code`, `client_id`, `redirect_uri=<engine-resolved>`, `scope`, `code_challenge`, `code_challenge_method=S256`, `id_token_add_organizations=true`, `codex_cli_simplified_flow=true`, `originator=codex_cli_rs`, `prompt=login`, `state`.
- [ ] **RED** — postExchange id_token: stub tokens `{access_token, refresh_token, id_token}` with a hand-built JWT whose payload has `email` + `https://api.openai.com/auth` claim `{chatgpt_account_id, chatgpt_plan_type:"free", chatgpt_user_id, organizations:[{id:"org-1", is_default:true, role:"member", title:"Personal"}, {id:"org-2", is_default:false, role:"admin", title:"Acme Team"}]}` → workspaceId "org-2", planType "team", meta carries organizations array; planType "team" case → chatgpt_account_id kept; no id_token → authInfo null, email null, connect still fine.
- [ ] **RED** — refresh: default standardRefresh (assert no scope in body); terminal-error classification already engine-level (Task 2's msg/code + existing invalid_grant handling in standardRefresh throwing `error`).
- [ ] **GREEN** + **Commit:** `oauth: codex adapter (id_token workspace selection)`

## Task 12 — xai-oauth adapter

**Files:** `src/oauth/providers/xai-oauth.ts` (new), `registry.ts`, `test/oauth-xai.test.ts` (new).

**Interfaces:** `prefix: "xai-oauth"`, `flowMode: "paste-code"`, `redirectUri: "http://127.0.0.1:56121/callback"`, `pkceVerifierBytes: 96` (types.ts field already landed in Task 1's interface block; the ENGINE one-liner `generatePkce(a.pkceVerifierBytes ?? 32)` lands HERE, RED-first — see step 1).

**Steps:**
- [ ] **RED (engine flag)** — in this test file, register a TEST adapter (`registerAdapter`, prefix `xv-test`, paste-code, no static redirectUri, `pkceVerifierBytes: 96`) → start → assert the verifier/challenge pair derives from a 128-char verifier (96 bytes). Watch it FAIL (engine ignores the flag, uses 32) → **GREEN** adds the one-liner `generatePkce(a.pkceVerifierBytes ?? 32)` in the paste-code branch → re-run → pass.
- [ ] **RED** — buildAuthUrl: 9 params incl. `nonce` (32 hex chars), `plan=generic`, `referrer=cli-proxy-api`; redirect_uri = the loopback constant.
- [ ] **RED** — exchangeToken: standard 5 fields; mapTokens: id_token identity (email/preferred_username, name), meta `scope`, `tokenType`; label name || email.
- [ ] **RED** — refresh: default standardRefresh.
- [ ] **GREEN** + **Commit:** `oauth: xai-oauth adapter (96-byte verifier, loopback constant)`

## Task 13 — grok-cli adapter (device primary + paste import)

**Files:** `src/oauth/providers/grok-cli.ts` (new), `registry.ts`, `test/oauth-grok-cli.test.ts` (new).

**Interfaces:** `prefix: "grok-cli"`, `flowMode: "device"`; config `{ clientId, issuer, deviceCodeUrl, tokenUrl, deviceScope (10-scope string), browserScope (4-scope string, unused this plan), oAuthHeaders }` where `oAuthHeaders()` → `{ Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded", "x-grok-client-version": "1.0.41", "x-grok-client-surface": "ui" }`.

**Steps:**
- [ ] **RED** — device start: deviceCodeUrl + deviceScope + `referrer=grok-build` body; validation: missing fields → 502; bad user_code charset → 502 "Grok returned an invalid device code"; `http://127.0.0.1:56122/...` verification URL ACCEPTED (isLocalHttp), `http://evil.com` rejected 502 "Grok returned an unsupported verification URL"; defaults 1800/5.
- [ ] **RED** — poll: tokenUrl + grant body + oAuthHeaders.
- [ ] **RED** — mapTokens dispatch (browser/device shape): `{access_token: "eyJ...", refresh_token, id_token, expires_in: 21600}` → accessToken/refreshToken/expiresIn, identity from id_token (email/name), meta `scope`, `tokenType`, `autoSync:true`; expiresIn 0/negative/NaN → clamped 1 (or 21600 default when absent — assert both).
- [ ] **RED** — device TTL (builder b8): device response `expires_in: 1800` → pending row TTL 1800 (engine Task-1 clamp — assert in this file too).
- [ ] **RED** — paste import via complete `{token}` (engine Task-10 rule; builder b10-iv): the engine wraps a string paste as `{access_token: "<raw>"}`, so the adapter's `importToken` must parse the STRING itself — try JSON.parse when it starts with `{` (auth.json blob / `{accessToken: ...}` wrapper), else treat as raw JWT. Cases: raw JWT string → mapImportedToken (claims: email, sub/principal_type/principal_id → userId/teamId/organizationId/tier; exp-based expiresIn); stringified auth.json blob `{accessToken: {"https://auth.x.ai::b1a00492-...": {key:"eyJ...", refresh_token:"r", expires_at:"2026-01-01T00:00:00Z"}}}` → key picked from preferred scope key first; stringified `{accessToken: "eyJ..."}` wrapped → plain JWT; refresh_token absent → meta lacks it, connect fine.
- [ ] **RED** — refresh: default standardRefresh against tokenUrl.
- [ ] **GREEN** + **Commit:** `oauth: grok-cli adapter (device + jwt/auth.json paste import)`

## Task 14 — cursor adapter (deep-control login + paste import)

**Files:** `src/oauth/providers/cursor.ts` (new), `registry.ts`, `test/oauth-cursor.test.ts` (new).

**Interfaces:** `prefix: "cursor"`, `flowMode: "device"`; config `{ loginUrl, pollUrl, refreshUrl, clientVersion: "2026.07.08-0c04a8a", clientType: "ide" }`.

**Steps:**
- [ ] **RED** — device start: `crypto.randomUUID()` uuid; loginUrl query `challenge=<engine challenge>&uuid=<uuid>&mode=login&redirectTarget=cli`; DeviceCodeResponse `{device_code: uuid, user_code: uuid, verification_uri: loginUrl, verification_uri_complete: loginUrl, expires_in: 900, interval: 2}`.
- [ ] **RED** — poll: GET `${pollUrl}?uuid=&verifier=` with NO custom headers; 404 → authorization_pending; 200 `{accessToken, refreshToken}` → ok; 200 missing tokens → `{error:"Cursor auth response missing tokens"}`; 500 → `Cursor auth poll failed: 500`.
- [ ] **RED** — mapTokens dual shape (grok pattern, builder b1): snake_case `{access_token, refresh_token}` (device/poll + refresh paths) → deep-control shape (JWT exp expiry, skew, email/accountId, meta authMethod "deep_control"); camelCase paste shape `{accessToken, machineId?, authMethod?}` → import shape. Missing refreshToken in poll response → connect FAILS (400) — deep-control always returns both.
- [ ] **RED** — paste import: `complete {token:"<50+ char JWT>"}` → authMethod "cursor-agent"; optional machineId format check (hex/uuid ≥32 → invalid → 400 "Invalid machine ID format."); paste object `{accessToken, refreshToken, machineId}` → authMethod "imported"; JWT exp fallback 86400; short token → 400 "Invalid token format. Token appears too short." (Reachable from the console via the Task-2 paste-token box.)
- [ ] **RED** — refresh hook (snake_case, builder b1): POST refreshUrl `Authorization: Bearer <refresh>`, JSON `{}`; success → `{access_token: data.accessToken, refresh_token: data.refreshToken || old}`; 401/403 → throw with name `CursorRefreshUnauthorized` → refresh.ts: add second adapter-agnostic rule `err.name === "CursorRefreshUnauthorized"` → unrecoverable; 503×2 then 200 (retryable) → 3 fetch attempts with ≥2 backoff waits (fake timers); all 3 attempts fail (503×3) → throw "Cursor token refresh failed after 3 attempts (last status 503)" — provider-specific `last_error` text per USER DECISION (transient failures surface verbatim; card shows reconnect-required until the next successful use).
- [ ] **GREEN** + **Commit:** `oauth: cursor deep-control adapter (+paste import, retrying refresh)`

## Task 15 — openference adapter

**Files:** `src/oauth/providers/openference.ts` (new), `registry.ts`, `test/oauth-openference.test.ts` (new).

**Steps:**
- [ ] **RED** — buildAuthUrl (URLSearchParams.toString() ordering: response_type, client_id, redirect_uri=loopback constant `http://127.0.0.1:56123/callback`, scope, code_challenge, code_challenge_method, state).
- [ ] **RED** — exchangeToken standard 5; postExchange userinfo best-effort; mapTokens identity fallback chain (id_token name/email → userinfo name/email/preferred_username); meta scope/tokenType; label name || email.
- [ ] **RED** — refresh: default standardRefresh.
- [ ] **GREEN** + **Commit:** `oauth: openference adapter`

## Task 16 — clinepass alias + cline/codebuddy refresh hooks

**Files:** `src/oauth/providers/clinepass.ts` (new — thin alias), `src/oauth/providers/cline.ts` (add refresh hook), `src/oauth/providers/codebuddy.ts` (add refresh hooks), `registry.ts`, `test/oauth-clinepass-refresh.test.ts` (new).

**Interfaces:**
- clinepass adapter: `prefix: "clinepass"`, everything else = cline adapter fields (spread + override prefix + label instructions "ClinePass — same Cline WorkOS sign-in"); `buildAuthUrl`/`exchangeToken`/`mapTokens` shared by reference (cline exposes NO importToken — its paste-code authorization code carries the base64 token blob itself).
- cline `refresh(config, refreshToken, meta)`: POST `https://api.cline.bot/api/v1/auth/refresh` JSON `{refreshToken, grantType:"refresh_token", clientType:"extension"}`; response `data = payload.data || payload`; expiresIn from `data.expiresAt` (ISO → max(1, floor((t−now)/1000))); rotate-in; error body containing `invalid_grant`/`invalid_request` (substring match, embedded style) → throw "cline refresh rejected: invalid_grant" (terminal). Missing refreshUrl → throw.
- codebuddy-cn/intl `refresh` (OmniRoute `codebuddyShared.ts` verbatim): POST `config.refreshUrl`, headers `{ "Content-Type": "application/json", "Accept": "application/json", "User-Agent": config.userAgent, "X-Requested-With": "XMLHttpRequest", "X-Domain": config.domain, "X-Refresh-Token": refreshToken, "X-Auth-Refresh-Source": "plugin", "X-Product": "SaaS" }`, body `{}`. Success `{code:0, data:{accessToken, refreshToken?, expiresIn}}` → rotate-in `data.refreshToken || old`. `code !== 0` or missing `data.accessToken` → throw "CodeBuddy token refresh returned no token" (→ last_error, reconnect per refresh.ts). HTTP non-ok → throw "Failed to refresh CodeBuddy token (<status>)". (Same shape serves workbuddy Task 9 — workbuddy adds its own `X-Domain: www.workbuddy.ai` + `User-Agent: WorkBuddy/5.5.6`.)

**Steps:**
- [ ] **RED** — clinepass: start/complete behave identically to cline under its own prefix (reuse Plan-1 cline test shape with prefix swapped; blob/code paths unchanged).
- [ ] **RED** — cline refresh: success shape (envelope + expiresAt math + rotate-in); embedded invalid_grant → terminal.
- [ ] **RED** — codebuddy refresh ×2 (cn/intl): correct refreshUrl + UA/X-Domain per config; success + failure shapes.
- [ ] **GREEN** + **Commit:** `oauth: clinepass alias + cline/codebuddy refresh hooks`

## Task 17 — Console instructions pass + README + final verification

**Files:** `src/oauth/providers/*.ts` (instructions strings review), `README.md`, final ledger.

**Steps:**
- [ ] Instructions strings for all 13 (device flows: "Open <verification_uri> and confirm code <user_code>"; paste-code: "Open the URL, sign in, copy the code from the callback address bar"; claude/cursor/grok mention the token-paste alternative — reachable via the Task-2 console paste-token box; ghe-copilot carries the manual `?gheUrl=` start line; codex notes its callback lands on the gateway itself and auto-completes via the public state-matched callback). No code changes beyond strings — covered by existing list-render test asserting `instructions` passthrough (extend one test to a Plan-2 adapter).
- [ ] README: Wave B Plan 2 section — provider table (prefix / flow / how to connect / refresh behavior), carry-over fixes list, secrets unchanged. Hinglish tone matching repo convention. Must document: the public state-matched callback (what it trusts and why), the console paste-token box, and the ghe-copilot manual start (`POST /admin/api/oauth/ghe-copilot/start?gheUrl=https://<ghe-host>`).
- [ ] Final: `npm test` all green + `npm run test:miniflare` green + `npm run typecheck` clean; update `.superpowers/sdd/.../progress.md` ledger (LANDED section, rulings).
- [ ] **Commit:** `docs: wave B plan 2 providers landed`

---

## Out of scope (ledgered, NOT this plan)

- Forwarding/chat integration for any provider (separate plan — user decision 2026-11-16).
- Browser-PKCE variants (devin-desktop, grok browser-PKCE `supportsBrowserPkce`) — device + paste cover workers.dev UX.
- `copilotCapabilities` discovery (github), minimax local-profile write (`persistProfileCredential`), deviceFlowTickets (codex remote-login helper), pasteCredentials blob gate (Google-only), `pkceLoopbackWarning` UX copy (superseded by per-provider instructions), `authHeaders(token)` forward hook, `missing-token:<prefix>` fallback tag rename (lands with forwarding), codebuddy UA npm auto-refresh (static pin accepted), minimax `cn` region plumbing (static `en`; ledger if a cn account shows up), muse `MUSE_CODE_MAX_POLL_MS` (client-side console TTL already bounds polling).
- kiro / amazon-q (ToS), devin-cli, qoder, zed, gitlab-duo, antigravity/agy, copilot-m365-web, megabrain, renderhour (Plan 3 hosted batch).

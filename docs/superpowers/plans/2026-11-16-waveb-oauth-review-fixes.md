# Wave B OAuth Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve the confirmed credential-at-rest issue and four important OAuth review findings without changing forwarding scope.

**Architecture:** Add one nullable encrypted `provider_secrets` field for sensitive provider-specific credentials while keeping `meta` non-secret JSON. Scrub known legacy secret fields during token reads, then fix import validation, metadata merging, and reconnect-required status as separate TDD tasks.

**Tech Stack:** Cloudflare Workers TypeScript, D1 migrations, Web Crypto AES-GCM, Vitest.

**Spec:** `docs/superpowers/specs/2026-11-16-waveb-oauth-review-fixes-design.md`; parent security contract: `docs/superpowers/specs/2026-11-16-waveb-oauth-design.md`.

## Global Constraints

- Web-standard APIs only in `src/`; no Node APIs.
- OAuth access/refresh/provider secrets use `OAUTH_ENCRYPTION_KEY` and AES-GCM; plaintext `meta` contains non-secret data only.
- Do not log tokens or include them in API/list/status responses.
- Use mocked provider fetches and local D1 stubs; no live provider calls.
- Preserve existing OAuth response envelopes and refresh-on-use behavior.
- Do not implement JWT signature verification; Grok imports require a valid three-part token with a decodable object payload.
- No chat-forwarding, Copilot-token renewal, or Miniflare dependency changes.

## Review Focus

- Legacy D1 rows containing plaintext `copilotToken` or duplicate `dcaToken`: encrypt/move or remove the secret and scrub plaintext without overwriting concurrent token updates.
- Corrupt or malformed Grok JWT/auth.json values: reject with HTTP 400 and do not create a connection.
- Claude setup-token validation statuses other than 401/403/5xx: reject all non-2xx responses before persistence.
- Refresh responses omitting identity/profile fields: preserve prior non-secret metadata and encrypted provider secrets.
- Expired connections with no refresh grant: persist reconnect-required `last_error` before returning the existing `TokenExpiredError`.

---

### Task 1: Encrypt provider-specific secrets and scrub legacy metadata

**Files:**
- Create: `migrations/0005_oauth_provider_secrets.sql`
- Modify: `src/oauth/types.ts`, `src/oauth/store.ts`, `src/oauth/engine.ts`
- Modify: `src/oauth/providers/github.ts`, `src/oauth/providers/ghe-copilot.ts`, `src/oauth/providers/muse-code.ts`
- Test: `test/oauth-store.test.ts`, `test/oauth-github.test.ts`, `test/oauth-ghe-copilot.test.ts`, `test/oauth-muse.test.ts`
- Update D1 stubs that record `INSERT INTO oauth_tokens`.

**Interfaces:**
- `MappedTokens`, `SaveTokenInput`, and decrypted `TokenRow` gain optional `secrets?: Record<string, unknown>`.
- `OAuthAdapter.mapTokens(tokens, extra?, priorMeta?, priorSecrets?)` receives old encrypted secrets only on refresh.
- `oauth_tokens.provider_secrets BLOB` stores AES-GCM-encrypted serialized secrets; `meta` remains non-secret JSON.

- [x] **Step 1: Write failing storage and adapter tests**
  - Store test saves `{copilotToken:"copilot-secret"}` in `secrets` and ordinary profile data in `meta`; raw D1 row must contain neither credential string, while `getToken()` must decrypt both fields into their respective properties.
  - GitHub/GHE tests assert `copilotToken` is absent from `row.meta`, present in decrypted `row.secrets`, and absent from raw D1 text.
  - Muse connect/refresh tests assert the DCA value exists in encrypted `refresh_token`, never in `meta`, and that `meta.dcaToken` is removed.
  - Legacy-row test seeds old plaintext metadata and verifies `getToken` and status reads scrub it, encrypt the Copilot token, remove the duplicate Muse DCA field, and preserve unrelated metadata.
- [x] **Step 2: Run focused tests and verify RED**

  Run: `npm test -- test/oauth-store.test.ts test/oauth-github.test.ts test/oauth-ghe-copilot.test.ts test/oauth-muse.test.ts`

  Expected: FAIL because the store has no encrypted provider-secret field and the adapters currently map credentials into `meta`.
- [x] **Step 3: Add additive migration and encrypted store support**
  - Add `ALTER TABLE oauth_tokens ADD COLUMN provider_secrets BLOB`.
  - Encrypt/decrypt serialized secrets with the existing AES-GCM token helpers; treat corrupt ciphertext as a reconnect-required corrupt row.
  - On `getToken()` and `getTokenStatus()`, detect the known legacy keys `copilotToken` and `dcaToken`; move `copilotToken` into encrypted secrets and remove both keys from plaintext metadata. Condition the rewrite on both original `meta` and `provider_secrets` values still matching.
- [x] **Step 4: Thread and map secrets**
  - Pass `row.secrets` as the fourth `mapTokens` argument on refresh and preserve `row.secrets` in the refresh save when the mapper omits secrets.
  - GitHub and GHE map Copilot bearer tokens to `secrets.copilotToken`; keep token expiry and non-secret profile/endpoint fields in metadata.
  - Muse maps its DCA only to the encrypted refresh-token field and strips legacy metadata copies.
- [x] **Step 5: Run focused tests**

  Run: `npm test -- test/oauth-store.test.ts test/oauth-github.test.ts test/oauth-ghe-copilot.test.ts test/oauth-muse.test.ts`

  Expected: PASS, including raw-row plaintext absence and legacy cleanup.
- [x] **Step 6: Run full suite and typecheck**

  Run: `npm test` and `npm run typecheck`

  Expected: all tests pass; TypeScript exits 0.
- [x] **Step 7: Commit**

  Commit: `security: encrypt provider OAuth secrets`

### Task 2: Reject malformed Grok token imports

**Files:**
- Modify: `src/oauth/providers/grok-cli.ts`
- Test: `test/oauth-grok-cli.test.ts`

**Interfaces:**
- Keep `importToken` response shape unchanged; invalid raw JWTs and auth.json keys throw an adapter error that the engine exposes as HTTP 400.

- [x] **Step 1: Add failing tests** for arbitrary text, malformed segment count, invalid base64/JSON payload, and malformed auth.json `key`; through `complete()`, each returns HTTP-class `OAuthError(400)` and writes no token row. Keep a valid unsigned three-part fixture passing.
- [x] **Step 2: Run RED**

  Run: `npm test -- test/oauth-grok-cli.test.ts`

  Expected: invalid strings currently connect instead of rejecting.
- [x] **Step 3: Validate JWT structure before mapping**
  - Require exactly three non-empty JWT segments and a decodable object payload using the existing web-standard `decodeJwtPayload`.
  - Apply the check equally to raw strings, wrapped access tokens, and selected auth.json keys; do not add signature verification.
- [x] **Step 4: Run focused test**

  Run: `npm test -- test/oauth-grok-cli.test.ts`

  Expected: PASS; malformed inputs create no row.
- [x] **Step 5: Run full suite and typecheck**

  Run: `npm test` and `npm run typecheck`

  Expected: all tests pass; TypeScript exits 0.
- [x] **Step 6: Commit**

  Commit: `fix: reject malformed Grok token imports`

### Task 3: Fail closed on Claude setup-token validation

**Files:**
- Modify: `src/oauth/providers/claude.ts`
- Test: `test/oauth-claude.test.ts`

**Interfaces:**
- Preserve `Invalid OAuth token` for 401/403 and `Provider unavailable (<status>)` for 5xx; return an explicit validation failure for other non-2xx statuses.

- [x] **Step 1: Add failing tests** for HTTP 400 and 429 validation responses; assert HTTP 400 completion error and no stored token row. Keep existing 401/403/5xx behavior tests.
- [x] **Step 2: Run RED**

  Run: `npm test -- test/oauth-claude.test.ts`

  Expected: 400 and 429 currently fall through and save the setup token.
- [x] **Step 3: Reject every non-2xx response before mapping**
  - Accept only `response.ok`; retain specific existing error messages for 401/403 and 5xx.
- [x] **Step 4: Run focused test**

  Run: `npm test -- test/oauth-claude.test.ts`

  Expected: PASS; all rejected validation responses leave no row.
- [x] **Step 5: Run full suite and typecheck**

  Run: `npm test` and `npm run typecheck`

  Expected: all tests pass; TypeScript exits 0.
- [x] **Step 6: Commit**

  Commit: `fix: reject unsuccessful Claude token validation`

### Task 4: Preserve safe provider metadata through refresh

**Files:**
- Modify: `src/oauth/providers/github.ts`, `src/oauth/providers/grok-cli.ts`, `src/oauth/providers/cline.ts`
- Test: `test/oauth-github.test.ts`, `test/oauth-grok-cli.test.ts`, `test/oauth-clinepass-refresh.test.ts`

**Interfaces:**
- GitHub/Grok mappers accept `priorMeta` and `priorSecrets`; Cline mapper accepts `priorMeta`.
- Fresh upstream fields override saved values; omitted fields preserve prior values. Secret fields remain in Task 1's encrypted `secrets`, never in `meta`.

- [x] **Step 1: Add failing refresh tests** for GitHub, Grok, and Cline where upstream refresh payloads omit profile fields; assert connected label/profile metadata and GitHub encrypted Copilot secret survive.
- [x] **Step 2: Run RED**

  Run: `npm test -- test/oauth-github.test.ts test/oauth-grok-cli.test.ts test/oauth-clinepass-refresh.test.ts`

  Expected: current mappers overwrite previously saved metadata.
- [x] **Step 3: Merge prior metadata in each mapper**
  - Preserve non-secret values from `priorMeta`; use fresh upstream/profile fields when supplied.
  - For GitHub, preserve `priorSecrets` when refresh does not supply a new Copilot token.
- [x] **Step 4: Run focused tests**

  Run: `npm test -- test/oauth-github.test.ts test/oauth-grok-cli.test.ts test/oauth-clinepass-refresh.test.ts`

  Expected: PASS with preserved and updated values.
- [x] **Step 5: Run full suite and typecheck**

  Run: `npm test` and `npm run typecheck`

  Expected: all tests pass; TypeScript exits 0.
- [x] **Step 6: Commit**

  Commit: `fix: preserve provider metadata during OAuth refresh`

### Task 5: Record reconnect status when no refresh grant exists

**Files:**
- Modify: `src/oauth/refresh.ts`
- Test: `test/oauth-refresh.test.ts`

**Interfaces:**
- Preserve `TokenExpiredError(prefix, "token expired, no refresh grant")`; set the same specific reason in the provider row's `last_error` before throwing.

- [x] **Step 1: Add failing test** for an expired connected row without `refreshToken`; assert `ensureFreshToken()` throws the existing error and `getTokenStatus()` reports the reconnect-required `lastError`.
- [x] **Step 2: Run RED**

  Run: `npm test -- test/oauth-refresh.test.ts`

  Expected: error is thrown, but `lastError` remains null.
- [x] **Step 3: Mark the row before throwing**
  - Use the existing `markTokenError` helper and preserve the current exception detail.
- [x] **Step 4: Run focused test**

  Run: `npm test -- test/oauth-refresh.test.ts`

  Expected: PASS; status exposes the stored reason.
- [x] **Step 5: Run final verification**

  Run: `npm test`, `npm run typecheck`, and `git diff --check`.

  Expected: all tests pass, typecheck exits 0, no whitespace errors.
- [x] **Step 6: Record review rulings and deferred minors; commit**

  Commit: `fix: mark expired OAuth tokens for reconnect`

## Review Rulings and Deferred Items

### Deferred minor findings

- Admin UI in-flight polling behavior remains deferred as a UX-only follow-up.
- Constant-time OAuth state comparison remains deferred; existing high-entropy, one-time state handling is unchanged by this patch.
- Callback `Cache-Control` hardening remains deferred as a minor HTTP-header improvement.
- README setup-token wording remains deferred as a documentation-only correction.

### Accepted scope rulings

- **Miniflare:** no dependency changes; the repository uses Vitest 5 while the available Miniflare worker-pool integration requires a Vitest 4 peer range. Unit tests and the local Wrangler D1 migration smoke are used instead.
- **Public state-gated callback:** intentionally remains public because the provider redirects to it; the callback is gated by the one-time OAuth state/verifier flow.
- **GHE manual start:** the endpoint remains admin-authenticated and manually invoked with a GHE URL; adding a UI was outside this OAuth security fix.
- **Cursor poll envelope:** preserve the provider-specific existing response shape; normalizing it is unrelated to the reviewed findings.
- **Forwarding and Copilot renewal:** out of scope. This work stores Copilot credentials encrypted but does not add forwarding or renewal behavior.
- **JWT signatures:** Grok imports validate the compact three-segment form and decode an object payload only; signature verification remains explicitly out of scope.

After all five task commits, perform one fresh whole-branch review and append its result here.

### Final whole-branch review (HEAD `8931d76`)

- Reviewer verdict: **Ready to merge — no Critical, Important, or Minor issues.**
- Reviewer recommendation: apply migration `0005_oauth_provider_secrets.sql` before deploying code that reads or writes `provider_secrets`.
- The prior review's two Important findings were fixed in `8931d76` (`fix: scrub OAuth secrets when migration fails`): legacy plaintext is now removed by compare-and-set even when encrypted-secret migration fails (corrupt ciphertext or missing key), with a reconnect-required `last_error`; status reads decrypt-validate any non-null `provider_secrets` and flag corrupt ciphertext.
- Independent verification at `8931d76`: 495 tests across 45 files pass, `npm run typecheck` passes, `git diff --check` is clean, and D1 migrations 0001–0005 applied locally.

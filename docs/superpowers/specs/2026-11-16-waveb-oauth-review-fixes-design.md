# Wave B OAuth review fixes — Design

## Intent

Bring the completed Wave B OAuth batch back in line with the approved security
spec and review findings: provider credentials must be encrypted at rest, token
imports must fail closed, refreshes must preserve safe account metadata, and an
expired connection without a refresh grant must visibly require reconnecting.

## Goals

- Keep `oauth_tokens.meta` as readable, non-secret provider metadata.
- Store provider-specific credentials in an additive AES-GCM encrypted D1
  `provider_secrets` column using the existing `OAUTH_ENCRYPTION_KEY`.
- Move GitHub/GHES Copilot bearer tokens out of `meta`; keep Muse's DCA only in
  its already encrypted `refresh_token`.
- On reads of legacy rows, move the known Copilot token into encrypted secrets
  and scrub both `copilotToken` and duplicate `dcaToken` fields from plaintext
  metadata. Apply the rewrite only if both the original metadata and encrypted
  secret column still match, so a concurrent refresh/upsert is not overwritten.
- Reject malformed Grok JWT imports and every non-2xx Claude setup-token
  validation response before saving a connection.
- Preserve prior non-secret metadata and provider secrets when refresh
  responses omit them.
- Record a reconnect-required `last_error` when an expired token has no refresh
  grant.

## Non-goals

- JWT signature verification; Grok imports will require a decodable JWT
  structure, matching this gateway's existing payload-decoding model.
- OAuth forwarding changes, Copilot-token renewal, Miniflare installation, or
  unrelated minor review suggestions.

## Approaches considered

1. **Dedicated encrypted `provider_secrets` column — selected.** This keeps the
   plaintext `meta` contract non-secret, preserves provider credentials for
   future use, and uses the existing key/crypto path. It requires an additive
   migration and a typed adapter/store field.
2. Encrypt the entire `meta` JSON. This avoids a new column but violates the
   approved spec's explicit non-secret metadata contract and changes the
   storage meaning of `meta`.
3. Drop Copilot tokens rather than persist them. This avoids schema work but
   discards adapter data that the provider flow currently obtains and would
   need for later forwarding integration.

The user approved approach 1 by asking to continue after it was recommended.

## Design

- Add nullable `provider_secrets BLOB` via a new D1 migration. Encrypt its
  serialized object with the same AES-GCM primitive used for access and refresh
  tokens. Add optional `secrets` fields to mapped tokens, saved inputs, and
  decrypted token rows; never include them in status/list responses.
- Extend the engine refresh mapping call with prior secrets so adapters can
  retain them when upstream refresh payloads omit provider-specific values;
  the refresh save also falls back to `row.secrets` if a mapper omits secrets.
- GitHub and GHE mappers place `copilotToken` in `secrets`; expiry, endpoint,
  host, and profile fields remain in `meta`. Muse's DCA remains the encrypted
  refresh token; its mapper strips legacy `dcaToken` from metadata.
- Store reads detect legacy `copilotToken` / `dcaToken` metadata, encrypt and
  persist the Copilot token where present, and remove both plaintext fields
  from `meta`. The rewrite is conditional on both the original `meta` and
  `provider_secrets` values still matching to avoid overwriting a concurrent
  update.
- Grok paste import accepts only a JWT with three segments and a decodable
  object payload. Claude setup-token import accepts only successful 2xx
  validation; existing 401/403 and server-error messages remain specific.
- GitHub, Grok CLI, and Cline refresh mapping merges `priorMeta` with returned
  values, preferring fresh values and preserving old non-secret fields when
  refresh omits them.
- `ensureFreshToken` marks the provider row with a reconnect-required error
  before throwing when an expired token has no refresh grant.
- Add regression tests first for each finding, including raw D1 assertions,
  legacy metadata scrubbing, invalid-paste row absence, refresh metadata
  preservation, and stored refresh error status. Run focused tests, the full
  suite, typecheck, and diff checks.

## Constraints

- Workers code remains web-standard TypeScript with no Node APIs.
- No live provider calls; tests use mocked fetch and local D1 stubs.
- Preserve existing OAuth response envelopes and single-use pending-flow
  behavior.

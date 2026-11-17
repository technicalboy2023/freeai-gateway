# Plan: FreeAI Gateway — Cloudflare Worker (v1 / Phase A)

## Spec
Design was brainstormed and approved in conversation (2026-11-15).
Summary: A single-endpoint, OpenAI-compatible AI gateway hosted FREE on
Cloudflare Workers (100k req/day, no card). Multiple AI providers behind one
endpoint, any AI tool can connect. Auth-protected. Streaming + fallback.
OAuth providers (Wave B) and multimodal (Phase C) are FOLLOW-UP plans — this
plan covers Phase A (base gateway) only.

## Global Constraints
- TypeScript, Cloudflare Workers runtime (Web-standard APIs only; no Node APIs in src/)
- Provider keys come ONLY from Worker secrets (env), never hardcoded, never committed
- Gateway auth: single Bearer `GATEWAY_KEY` secret; 401 otherwise
- All model routing uses `provider/model` prefixes (e.g. `groq/llama-3.3-70b`)
- Tests: vitest, unit-level with mocked `fetch`; run `npm test` after each task
- No network calls to real AI providers in tests
- Commits per task, conventional style: `feat(gateway): ...`
- Provider set (Phase A): groq, gemini, openrouter, nvidia, mistral, opencode-zen, openai, anthropic

## Interfaces
- `src/providers.ts` — provider registry: resolve(prefix), list(). Consumed by proxy, fallback, models.
- `src/auth.ts` — checkAuth(request, env) → Response | null. Consumed by every endpoint.
- `src/fallback.ts` — withFallback(chain, attempt). Consumed by proxy endpoints.
- `src/index.ts` — fetch handler wiring routes to all modules.

## Task 1: Scaffold + test infra
Config/scaffolding task (TDD-exception; user approved start).
Steps:
1. `package.json` (name freeai-gateway, type module, scripts: test→vitest run, deploy→wrangler deploy), `tsconfig.json`, `wrangler.jsonc` (name freeai-gateway, main src/index.ts, compatibility_date latest stable, minimal).
2. `src/index.ts` exporting a `default` ExportedHandler with `/` health JSON `{name:"freeai-gateway", status:"ok"}`.
3. `test/index.test.ts` — health test using a stubbed Request/env.
4. Install dev deps: vitest, typescript, wrangler, @cloudflare/workers-types.
Expected: `npm test` → 1 passing. `npx tsc --noEmit` clean.
Commit: `feat(gateway): scaffold worker + vitest`

## Task 2: Provider registry (TDD)
RED: `test/providers.test.ts`
- resolves `groq/llama-3.3-70b` → {prefix:"groq", baseURL:"https://api.groq.com/openai/v1", auth:"bearer", keySecret:"GROQ_API_KEY", model:"llama-3.3-70b"}
- resolves `gemini/gemini-3.5-flash` → baseURL `https://generativelanguage.googleapis.com/v1beta/openai`, auth "bearer", keySecret "GEMINI_API_KEY"
- resolves `openrouter/deepseek-r1:free` → baseURL `https://openrouter.ai/api/v1`
- resolves `nvidia/deepseek-v4.1-flash` → `https://integrate.api.nvidia.com/v1`
- resolves `mistral/mistral-large-latest` → `https://api.mistral.ai/v1`
- resolves `zen/gpt-5.5` → `https://opencode.ai/zen/v1`
- resolves `openai/gpt-4o` → `https://api.openai.com/v1`
- resolves `anthropic/claude-sonnet-4` → anthropic-style: baseURL `https://api.anthropic.com/v1`, auth "anthropic"
- unknown prefix → null (caller returns 404 JSON)
- `list()` returns enabled providers' model aliases
GREEN: implement registry. Commit: `feat(gateway): provider registry`

## Task 3: Gateway auth (TDD)
RED: `test/auth.test.ts`
- no Authorization header → 401 JSON
- wrong Bearer key → 401 JSON
- correct key === env.GATEWAY_KEY → returns null (proceed)
GREEN: `src/auth.ts`. Commit: `feat(gateway): bearer auth`

## Task 4: /v1/chat/completions proxy (TDD)
RED: `test/chat.test.ts` (mock global.fetch)
- correct provider forwarded to baseURL with `Authorization: Bearer <key>`; body forwarded with model stripped of prefix
- provider env key missing → 400 JSON naming the secret
- upstream 4xx/5xx body+status passed through
- `stream:true` response returned as-is (SSE headers preserved, body is ReadableStream)
GREEN: `src/chat.ts` using registry. Commit: `feat(gateway): chat completions proxy`

## Task 5: /v1/messages (Anthropic wire) (TDD)
RED: `test/messages.test.ts`
- anthropic provider: forwards to `https://api.anthropic.com/v1/messages` with `x-api-key` + `anthropic-version: 2023-06-01`
- missing ANTHROPIC_API_KEY → 400 JSON
- streaming passthrough same as Task 4
GREEN: `src/messages.ts` (shared helper with chat where reasonable). Commit: `feat(gateway): anthropic messages endpoint`

## Task 6: Fallback chain (TDD)
RED: `test/fallback.test.ts`
- env `FALLBACK_CHAINS` JSON like {"fast":["groq","gemini","openrouter"]}; model `fast/any-model` tries groq → on 429/5xx tries gemini → success returns gemini response
- all fail → 502 JSON listing attempts
- first success short-circuits
GREEN: `src/fallback.ts` + route integration. Commit: `feat(gateway): fallback chains`

## Task 7: /v1/models + CORS + OPTIONS (TDD)
RED: `test/models.test.ts`
- `/v1/models` → JSON OpenAI-style list built from registry (provider-prefixed ids)
- OPTIONS any path → 204 with CORS headers (Access-Control-Allow-Origin: *, Methods, Headers incl. Authorization)
- normal responses carry CORS headers
GREEN: `src/models.ts`, CORS helper in index. Commit: `feat(gateway): models list + CORS`

## Task 8: README + connect docs (config/doc task; TDD-exception)
Steps: README.md — setup (Cloudflare account, wrangler login, secret put commands for each provider, deploy, curl smoke tests non-stream + stream), connect snippets for Claude Code (ANTHROPIC_BASE_URL/AUTH_TOKEN), OpenAI-SDK tools (baseURL), chatbot apps (CORS), Fallback chains example.
Expected: file exists; no test. Commit: `docs(gateway): connect guide`

## Completion
- `npm test` all green; `npx tsc --noEmit` clean
- Final review pass over whole branch
- Deploy is a user-assisted step (needs their Cloudflare login) — out of scope for this session's tasks; README covers it.

## Review Focus
- Secret leakage paths (keys must never appear in responses/logs)
- Streaming correctness under Workers runtime constraints (10ms CPU)
- 401 vs 400 semantics

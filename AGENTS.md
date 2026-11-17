# AGENTS.md

## FreeAI Gateway — Cloudflare Worker (TypeScript)

Single OpenAI-compatible AI gateway on Cloudflare Workers. Plan: `plans/freeai-gateway.md`.

## Commands (verified on this machine)

- Install deps: `npm install`
- Run tests: `npm test` (vitest run; watch mode: `npx vitest`)
- Run single test file: `npm test -- test/index.test.ts`
- Typecheck: `npm run typecheck` (tsc --noEmit)
- Local dev server: `npm run dev` (wrangler dev; needs workerd, approved in allowScripts)
- Deploy: `npm run deploy` (wrangler deploy; needs `npx wrangler login` first)
- Secrets: `npx wrangler secret put NAME`
- Local D1 tables: `npx wrangler d1 migrations apply freeai-gateway-db --local`

## Layout / ownership

- `src/` — worker code. Web-standard APIs only (Request/Response/fetch); no Node APIs.
- `test/` — vitest unit tests, mocked fetch; no real network calls to AI providers.
- `public/admin/` — admin console SPA (vanilla HTML/CSS/JS, no build step).
- `wrangler.jsonc` — worker config (name freeai-gateway, compat date 2026-11-16, D1 + ASSETS bindings).
- `plans/` — execution plans; `.superpowers/sdd/` — git-ignored SDD ledgers.

## Environment facts

- Node v26.13.1, npm 11.20.0 (verified).
- Git: system Git 2.56 (winget) at `C:\Program Files\Git\cmd`; portable MinGit bhi `C:\Users\ankush\tools\MinGit\cmd` pe available. Fresh terminals: git PATH pe hai. Stale harness shells: prefix `$env:Path = 'C:\Program Files\Git\cmd;' + $env:Path`.
- Python 3.13.17 (winget) at `%LOCALAPPDATA%\Programs\Python\Python313` — UI skill searches ke liye; stale shells mein full path ya PATH prefix chahiye (bare `python` Store alias mein phas jata hai).
- wrangler 4.162 verified: `d1 migrations apply --local` + assets binding (`run_worker_first`) dev smoke pass.
- npm allowScripts: esbuild + workerd approved (postinstall needed by wrangler).
- wrangler.jsonc D1 `database_id` abhi bhi "TODO-wrangler-d1-create" placeholder hai — user ko `npx wrangler d1 create freeai-gateway-db` chalake replace karna hai (deploy se pehle).

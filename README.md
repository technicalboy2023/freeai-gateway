# FreeAI Gateway

Ek hi OpenAI-compatible AI gateway — Cloudflare Workers pe **FREE** (₹0, no card), tere saare AI provider keys ke peeche. Koi bhi AI tool isko connect kar sakta hai: Claude Code, Cursor, VS Code, chatbot apps, scripts.

```
Claude Code ──┐
Cursor ───────┤   https://freeai-gateway.<subdomain>.workers.dev
Chatbot ──────┼──►  [FreeAI Gateway Worker]
Script ───────┘        ├── groq        (free, 30 RPM)
                       ├── gemini      (free, no card)
                       ├── openrouter  (free models)
                       ├── nvidia      (free, ~40 RPM)
                       ├── mistral     (free mode)
                       ├── zen         (opencode zen)
                       ├── openai      (apni key)
                       └── anthropic   (apni key)
```

## Features

- **Ek endpoint, 8 providers** — `provider/model` format (`groq/llama-3.3-70b-versatile`)
- **Auto fallback** — provider fail/429 ho to agla provider automatically try hota hai
- **Streaming SSE passthrough** — tool use/streaming break nahi hota
- **Bearer auth** — ek `GATEWAY_KEY` secret, keys Cloudflare secrets mein (code mein kabhi nahi)
- **CORS** — browser apps se seedha kaam karta hai
- **Admin console** — `/admin` pe poora control panel: provider on/off + test buttons, request logs, usage stats, fallback chain editor, playground

## Setup (one-time, 5 min)

### 1. Cloudflare account + login

- [dash.cloudflare.com](https://dash.cloudflare.com) pe free account banao (no card needed)
- Phir terminal mein:

```bash
npx wrangler login        # browser kholega → Allow
```

### 2. Secrets set karo (sirf jo providers use karna hai, wahi kaafi)

```bash
npx wrangler secret put GATEWAY_KEY        # khud ka strong password (e.g. openssl rand -hex 24 / password generator)

npx wrangler secret put GROQ_API_KEY       # console.groq.com → free key
npx wrangler secret put GEMINI_API_KEY     # aistudio.google.com → Get API key (free)
npx wrangler secret put OPENROUTER_API_KEY # openrouter.ai → Keys (free models :free)
npx wrangler secret put NVIDIA_API_KEY     # build.nvidia.com → free key
npx wrangler secret put MISTRAL_API_KEY    # console.mistral.ai → free mode
npx wrangler secret put ZEN_API_KEY        # opencode.ai/zen
npx wrangler secret put OPENAI_API_KEY     # platform.openai.com (paid)
npx wrangler secret put ANTHROPIC_API_KEY  # console.anthropic.com (paid)

npx wrangler secret put ADMIN_PASSWORD     # admin console ka password (alag hai GATEWAY_KEY se)
```

### 3. D1 database (admin console data ke liye)

```bash
npx wrangler d1 create freeai-gateway-db
# Output mein jo database_id mila, use wrangler.jsonc ke d1_databases block mein
# "TODO-wrangler-d1-create" ki jagah paste karo.

npx wrangler d1 migrations apply freeai-gateway-db --remote  # production tables
npx wrangler d1 migrations apply freeai-gateway-db --local   # local dev (npm run dev ke liye)
```

### 4. Deploy

```bash
npm install
npm run deploy
# → https://freeai-gateway.<your-subdomain>.workers.dev
```

### 5. Fallback chains (optional, recommended)

```bash
npx wrangler secret put FALLBACK_CHAINS
# value:
{"fast":["groq","gemini","openrouter"],"coder":["groq","nvidia","gemini"]}
```

Ab model `fast/koi-bhi-model` pehle groq ko, fail/429 pe gemini ko, phir openrouter ko try karega.

Chains console se bhi edit ho sakti hain (Fallbacks tab) — D1 mein save hota hai aur env secret ko override karta hai.

## Admin console

Browser mein kholo: `https://freeai-gateway.<your-subdomain>.workers.dev/admin`

Password = `ADMIN_PASSWORD` secret (GATEWAY_KEY se alag hai, sirf console ke liye). Unset ho to console 503 disabled dikhata hai.

**5 tabs:**

| Tab | Kya karta hai |
|---|---|
| **Overview** | Har provider ka card — on/off switch, Test button (key verify, tokens consume nahi hota), key-configured dot, free models list + **OAuth Providers grid** (connect/disconnect flows) |
| **Logs** | Har request ka row (time, provider, model, status, latency, stream, chain/attempt, error) — provider filter, limit, 5s auto-refresh |
| **Stats** | 7-day window: per-provider requests, errors, error rate, avg latency |
| **Fallbacks** | Chain editor — chain add/remove/rename, provider chips add/remove/reorder, Save |
| **Playground** | `provider/model` + prompt → direct provider call (GATEWAY_KEY nahi chahiye), SSE stream live |

Logs/stats aur chain-save D1 configured hone chahiye (warna clean 503 message). Provider disable karne pe gateway turant 400 deta hai jo provider ka naam batata hai — fallback chains disabled provider ko skip kar deti hain, aur `/v1/models` disabled provider ke models advertise nahi karta (jab D1 configured hai). Logs tab mein "Prune >30d" button purani rows delete karta hai (manual retention — D1 free tier limit se pehle).

## OAuth providers (Wave B — Plan 1)

Kuch providers API-key nahi maangte — unke tokens OAuth/device login se aate hain. Wave B Plan 1 ka engine **7 providers** connect karta hai, console ke Overview tab ke **"OAuth Providers"** grid se:

| Provider | Login flow | Kya karna hai |
|---|---|---|
| `trae` | paste | trae.ai popup auth, ya solo.trae.ai se Cloud-IDE-JWT (Authorization header) copy → paste (~14 din) |
| `devin-desktop` | paste | Devin session token paste karo (`devin-session-token$` prefix auto lag jaata hai) |
| `cline` | paste-code | "Start login" → Cline login page kholo → jo code wapas mile use paste karke "Complete" |
| `kilocode` | device | "Start login" → verification page kholo → approve karo; console khud poll karta hai |
| `freebuff` | device | "Start login" → freebuff.com login link → approve; console khud poll karta hai |
| `codebuddy-cn` | device | "Start login" → Tencent CodeBuddy auth page → approve; console poll karta hai |
| `codebuddy-intl` | device | Same, international (www.codebuddy.ai) |

**Ek baar setup (one-time):**

```bash
# 1. Naya D1 migration (oauth_tokens + oauth_pending tables):
npx wrangler d1 migrations apply freeai-gateway-db --remote   # production
npx wrangler d1 migrations apply freeai-gateway-db --local    # local dev

# 2. Token encryption key (32 bytes, base64url):
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | npx wrangler secret put OAUTH_ENCRYPTION_KEY
```

Ye key D1 mein store hue OAuth tokens ko AES-GCM se encrypt karti hai — bina key ke console 503 deta hai ("set OAUTH_ENCRYPTION_KEY secret first"). Key rotate karni ho to purane tokens re-connect karne padenge.

**Kaise kaam karta hai:**

- Tokens sirf **D1 mein encrypted** rehte hain; console/API responses mein token material kabhi nahi jaata (sirf connected/expiry/label metadata)
- **No cron** — tokens **refresh-on-use** hoti hain: forward call ke waqt expiry check, ho sake to refresh grant se rotate (warna "not connected" 400)
- Disconnect (card ka button) token + in-flight flow dono delete karta hai
- **Forwarding abhi in 7 providers ke liye live nahi hai** — upstream request formats Plans 2–3 mein aayenge (yahan sirf connect/store/refresh engine + console hai)

## OAuth providers (Wave B — Plan 2)

Plan 2 ke 13 adapters bhi Overview tab ke **OAuth Providers** grid se connect hote hain. Device flow mein verification URL aur code card par aate hain, aur console approval check karta rehta hai. `paste-code` flow mein login karke callback address bar se code copy karke **Complete** mein paste karo — Codex exception hai, jo gateway callback se khud complete hota hai.

| Prefix | Flow | Kaise connect karein | Refresh behavior |
|---|---|---|---|
| `github` | device | Start login → verification page par code confirm karo | GitHub standard refresh grant, jab refresh token available ho |
| `ghe-copilot` | device | GHES ke liye admin-authenticated manual API start zaroori hai (neeche); GitHub.com ke liye `github` card use karo | Saved GHES host par token refresh |
| `kimi-coding` | device | Start login → Kimi verification page par code confirm karo | Device-bound Kimi refresh token rotate hota hai |
| `muse-code` | device | Start login → Meta/Muse verification page par code confirm karo | Durable DCA se API key dobara mint hoti hai |
| `minimax-code` | device | Start login → MiniMax verification page par code confirm karo | MiniMax refresh grant, saved account metadata ke saath |
| `workbuddy` | device | Start login → WorkBuddy verification page par code confirm karo | WorkBuddy plugin refresh endpoint |
| `grok-cli` | device + token paste | Device login approve karo; alternatively supported Grok CLI JWT/auth.json token paste karo | Standard xAI OAuth refresh grant |
| `cursor` | device + token paste | Deep-control login approve karo; alternatively Cursor IDE/CLI token paste karo | Cursor custom refresh endpoint; temporary failures retry hote hain |
| `claude` | paste-code + token paste | Login ke baad callback URL ka code paste karo; ya Claude setup token paste karo | Claude refresh + zaroorat par setup-token bootstrap |
| `codex` | paste-code callback | OpenAI login ke baad callback gateway par aata hai aur state match hone par khud complete hota hai | Standard OpenAI OAuth refresh grant |
| `xai-oauth` | paste-code | Login ke baad loopback callback address bar se code copy karke paste karo | Standard xAI OAuth refresh grant |
| `openference` | paste-code | Login ke baad loopback callback address bar se code copy karke paste karo | Standard OAuth refresh grant |
| `clinepass` | paste-code | Cline WorkOS login complete karke returned code paste karo | Cline WorkOS refresh endpoint |

**GHE Copilot manual start:** card ko `gheUrl` dene ke liye logged-in admin session se ye API call karo (ghe-host tumhara HTTPS GitHub Enterprise Server host hai). Response ka `verification_uri` kholo aur `user_code` enter karo:

```http
POST /admin/api/oauth/ghe-copilot/start?gheUrl=https://<ghe-host>
```

**Token-paste box:** Claude, Cursor aur Grok CLI cards par **Or paste a token** textarea aur **Connect with token** button available hain. Ye provider-specific import flow hai; baaki cards par box tabhi aata hai jab adapter token import support karta hai. Submitted OAuth credentials encrypted D1 storage mein jaate hain — API/list responses token values return nahi karte.

**Public state-matched callback (Codex):** provider redirect par admin cookie nahi hoti (cookie `SameSite=Strict` hai), isliye Codex callback `/admin/oauth/codex/callback` public route hai. Public hone ka matlab open callback acceptance nahi: gateway sirf tab code exchange karta hai jab us provider ka pending PKCE flow ho, expire na hua ho, aur callback ka `state` encrypted D1 pending row ke one-time state se exact match kare. Callback ko state match ke bina `code` dena kaafi nahi. Match ke baad pending flow success ya failure dono mein consume hota hai; replay reject hota hai. Callback page token material nahi dikhata.

**Plan 1 carry-over fixes:** pending OAuth state/verifier encrypted aur single-use hain; admin-cookie ke bina state-gated callback support hai; token-paste import provider capability ke hisaab se route hota hai; console polling stale flows ko rokta hai aur `slow_down` respect karta hai; OAuth provider test/status, refresh error reporting, KiloCode envelope validation aur Cline/CodeBuddy refresh paths covered hain.

Plan 2 bhi **connect/store/refresh** tak limited hai — in providers ka chat forwarding alag integration work hai. Secrets setup mein koi naya provider secret nahi: OAuth ke liye existing `OAUTH_ENCRYPTION_KEY` aur admin console ke liye `ADMIN_PASSWORD` hi use hote hain; existing `GATEWAY_KEY` setup unchanged hai.

## Security notes

- Provider keys **sirf Cloudflare secrets** mein — D1, UI, ya kisi response mein kabhi nahi jaati (test buttons sirf status/latency return karte hain)
- Admin auth: `ADMIN_PASSWORD` → HMAC-SHA256 signed HttpOnly cookie (7 din, SameSite=Strict) — koi session table nahi, kuch leak hone ko nahi
- Saari `/admin/api/*` routes cookie check karti hain; GATEWAY_KEY bearer auth se poori tarah alag
- `/admin*` requests `run_worker_first` se pehle worker se pass hoti hain — asset routing tested. Note: console ka **static shell (HTML/CSS/JS) publicly serve hota hai** — koi secret nahi hota usme; saara sensitive data `/admin/api/*` ke peeche hai jo admin cookie maangta hai
- Login brute-force throttle: 5 galat attempts per IP → 15-min lockout (429), D1-backed, fail-open (D1 down ho to login block nahi hota)
- D1 down/misconfigured ho to **proxy traffic kabhi nahi rukta** — config reads env pe fall back, log writes swallow, disabled-checks fail-open

## Smoke test

```bash
GW=https://freeai-gateway.<your-subdomain>.workers.dev
KEY=<tera-GATEWAY_KEY>

# non-stream
curl -s $GW/v1/chat/completions \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"groq/llama-3.3-70b-versatile","messages":[{"role":"user","content":"hi"}]}'

# stream
curl -s -N $GW/v1/chat/completions \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gemini/gemini-2.0-flash","stream":true,"messages":[{"role":"user","content":"count 1 to 5"}]}'

# fallback chain
curl -s $GW/v1/chat/completions \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"fast/llama-3.3-70b-versatile","messages":[{"role":"user","content":"hi"}]}'
```

## Tools connect karna

### Claude Code (Anthropic wire)

```bash
export ANTHROPIC_BASE_URL="https://freeai-gateway.<your-subdomain>.workers.dev"
export ANTHROPIC_AUTH_TOKEN="<tera-GATEWAY_KEY>"
claude
```

`/v1/messages` route anthropic provider ko hit karta hai (`claude-sonnet-4-5` ya `anthropic/claude-sonnet-4-5` dono chalega).

### OpenAI-SDK tools (Cursor, VS Code extensions, scripts, chatbot apps)

```
Base URL: https://freeai-gateway.<your-subdomain>.workers.dev/v1
API Key:  <tera-GATEWAY_KEY>
Model:    groq/llama-3.3-70b-versatile   (provider/model format)
```

Python example:

```python
from openai import OpenAI
client = OpenAI(
    base_url="https://freeai-gateway.<your-subdomain>.workers.dev/v1",
    api_key="<tera-GATEWAY_KEY>",
)
resp = client.chat.completions.create(
    model="groq/llama-3.3-70b-versatile",
    messages=[{"role": "user", "content": "hi"}],
)
```

### Browser / chatbot apps

CORS enabled hai (`*`) — seedha fetch kar lo. Models list: `GET /v1/models`.

## Endpoints

| Route | Kya karta hai |
|---|---|
| `GET /` | Health check |
| `GET /v1/models` | Available models (provider-prefixed) |
| `POST /v1/chat/completions` | OpenAI wire — saare providers |
| `POST /v1/messages` | Anthropic wire — anthropic provider (Claude Code) |
| `GET /admin` | Admin console SPA (ADMIN_PASSWORD login) |
| `POST /admin/api/login` · `POST /admin/api/logout` · `GET /admin/api/me` | Console session |
| `GET /admin/api/providers` · `POST /admin/api/providers/:p/toggle|test` | Provider list/enable/test |
| `GET /admin/api/oauth` | OAuth adapters + connection state (no secrets) |
| `POST /admin/api/oauth/:p/start` · `POST /admin/api/oauth/:p/complete` | OAuth connect flows (paste / paste-code / device) |
| `GET /admin/api/oauth/:p/poll` · `GET /admin/api/oauth/:p/status` · `DELETE /admin/api/oauth/:p` | Device poll / status / disconnect |
| `GET /admin/api/logs?limit=` | Request logs (D1) |
| `GET /admin/api/stats` | 7-day per-provider stats (D1) |
| `GET /admin/api/fallbacks` · `PUT /admin/api/fallbacks` | Fallback chain editor (D1) |
| `POST /admin/api/playground` | Direct provider call (admin cookie) |

Model format: `provider/model` — `groq/llama-3.3-70b-versatile`, `gemini/gemini-2.0-flash`, `openrouter/deepseek/deepseek-r1:free`, `anthropic/claude-sonnet-4-5` (ya plain `claude-sonnet-4-5` in /v1/messages).

## Errors

- `401` — galat/missing GATEWAY_KEY (proxy) ya missing admin cookie (console)
- `400` — provider ka secret set nahi hai (message mein secret ka naam), ya provider console se disabled hai
- `404` — unknown provider/chain prefix
- `502` — fallback chain ke saare providers fail (message mein `attempts` list)
- `503` — ADMIN_PASSWORD unset (console disabled) ya D1 not configured (admin reads)

## Development

```bash
npm install
npm test          # vitest
npm run typecheck # tsc --noEmit
npm run dev       # wrangler dev (localhost:8787)
```

Secrets locally: `.dev.vars` file (git-ignored):
```
GATEWAY_KEY=test-key
ADMIN_PASSWORD=dev-test
GROQ_API_KEY=gsk_...
```

Local D1 (logs/console dev ke liye):
```bash
npx wrangler d1 migrations apply freeai-gateway-db --local
```

## Roadmap

- [x] Phase A — base gateway (8 API-key providers)
- [x] Wave D — Admin console (`/admin`: providers, logs, stats, fallbacks, playground)
- [x] Wave B Plan 1 — OAuth engine + 7 simple providers (trae, devin-desktop, cline, kilocode, freebuff, codebuddy-cn/intl)
- [ ] Wave B Plan 2–3 — standard OAuth batch (claude, codex, ...) + forwarding for the Plan-1 seven (Claude Code OAuth, Codex/ChatGPT, Antigravity, Copilot, ...)
- [ ] Phase C — multimodal (image/video), no-auth providers

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Window } from "happy-dom";
import gateway from "../src/index";
import { handleLogin } from "../src/admin/auth";
import { poll, registerAdapter } from "../src/oauth/engine";
import { MissingKeyMaterialError } from "../src/oauth/errors";
import { getPending, savePending } from "../src/oauth/store";
import type { Env } from "../src/env";
import type { OAuthAdapter, PollResult, RawTokens } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");

/* ---------- shared D1 stub (same pattern as admin-oauth.test.ts) ---------- */

function stubDb() {
  const config: Record<string, string> = {};
  const tokens = new Map<string, Record<string, unknown>>();
  const pending = new Map<string, Record<string, unknown>>();
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async <T,>() => {
          if (!sql.startsWith("SELECT")) return null;
          if (sql.includes("oauth_pending")) {
            const row = pending.get(String(params[0]));
            return row ? (row as T) : null;
          }
          if (sql.includes("oauth_tokens")) {
            const row = tokens.get(String(params[0]));
            return row ? (row as T) : null;
          }
          const key = params[0] as string;
          return key in config ? ({ value: config[key] } as T) : null;
        },
        run: async () => {
          if (sql.startsWith("INSERT INTO oauth_tokens")) {
            const [provider, access, refresh, expiresAt, label, meta, authKind, connectedAt, lastRefreshAt] =
              params as [string, ...unknown[]];
            tokens.set(provider, {
              provider,
              access_token: access,
              refresh_token: refresh ?? null,
              expires_at: expiresAt ?? null,
              account_label: label ?? null,
              meta: meta ?? null,
              auth_kind: authKind,
              connected_at: connectedAt,
              last_refresh_at: lastRefreshAt ?? null,
              last_error: null,
            });
          }
          if (sql.startsWith("UPDATE oauth_tokens")) {
            const row = tokens.get(String(params[1]));
            if (row) row.last_error = params[0];
          }
          if (sql.startsWith("DELETE FROM oauth_tokens")) tokens.delete(String(params[0]));
          if (sql.startsWith("INSERT INTO oauth_pending")) {
            const [provider, mode, state, codeVerifier, deviceCode, extra, createdAt, expiresAt] =
              params as [string, ...unknown[]];
            pending.set(provider, {
              provider,
              mode,
              state: state ?? null,
              code_verifier: codeVerifier ?? null,
              device_code: deviceCode ?? null,
              extra: extra ?? null,
              created_at: createdAt,
              expires_at: expiresAt,
            });
          }
          if (sql.startsWith("DELETE FROM oauth_pending")) pending.delete(String(params[0]));
          return { success: true };
        },
      }),
    }),
  } as unknown as D1Database;
  return { db, tokens, pending };
}

const ctx = { waitUntil: () => {} } as unknown as ExecutionContext;

function envWith(extra: Record<string, unknown> = {}): Env {
  return { ADMIN_PASSWORD: "adm-pass", OAUTH_ENCRYPTION_KEY: KEY, ...extra } as unknown as Env;
}

function adminReq(path: string, init: RequestInit = {}, cookie = ""): Request {
  const headers: Record<string, string> = {
    ...((init.headers as Record<string, string>) ?? {}),
  };
  if (cookie) headers.cookie = `admin_session=${cookie}`;
  return new Request(`https://gw.test${path}`, { ...init, headers });
}

async function adminCookie(env: Env): Promise<string> {
  const res = await handleLogin(
    new Request("https://gw.test/admin/api/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: "adm-pass" }),
    }),
    env,
  );
  return (res.headers.get("set-cookie") ?? "").match(/admin_session=([^;]*)/)![1];
}

/* ---------- carry-over fakes ---------- */

const cbExchange: { args: unknown[] | null } = { args: null };
const cbBuild: { redirect: string | null } = { redirect: null };
let cbFail = false;

function cbAdapter(): OAuthAdapter {
  return {
    prefix: "cbtest",
    flowMode: "paste-code",
    config: { authorizeUrl: "https://up.test/authorize" },
    buildAuthUrl: (_config: OAuthAdapter["config"], redirectUri: string, _state: string, _challenge: string) => {
      cbBuild.redirect = redirectUri;
      return `https://up.test/authorize?redirect_uri=${encodeURIComponent(redirectUri)}`;
    },
    exchangeToken: async (...args: unknown[]) => {
      cbExchange.args = args;
      if (cbFail) throw new Error("upstream said no");
      return { access_token: "cb-at", refresh_token: "cb-rt" };
    },
    mapTokens: (t: RawTokens) => ({ accessToken: String(t.access_token), expiresIn: 600 }),
  } as unknown as OAuthAdapter;
}

const devPoll: { result: PollResult } = {
  result: { ok: false, data: { error: "authorization_pending" } },
};

function msgAdapter(data: RawTokens): OAuthAdapter {
  return {
    prefix: "msgdev",
    flowMode: "device",
    config: {},
    requestDeviceCode: async () => ({
      device_code: "dc-1",
      user_code: "XY-1",
      verification_uri: "https://up.test/verify",
      expires_in: 300,
      interval: 5,
    }),
    pollToken: async () => ({ ok: false, data }),
    mapTokens: (t: RawTokens) => ({ accessToken: String(t.access_token), expiresIn: 300 }),
  } as unknown as OAuthAdapter;
}

registerAdapter(cbAdapter());
registerAdapter({
  prefix: "keytest",
  flowMode: "paste",
  config: {},
  importToken: async (raw: RawTokens) => raw,
  mapTokens: (t: RawTokens) => ({ accessToken: String(t.access_token), expiresIn: 600 }),
} as unknown as OAuthAdapter);
registerAdapter({
  prefix: "boxtest",
  flowMode: "device",
  config: {},
  importToken: async (raw: RawTokens) => raw,
  requestDeviceCode: async () => ({
    device_code: "dc-1",
    user_code: "XY-2",
    verification_uri: "https://up.test/verify",
    expires_in: 300,
    interval: 5,
  }),
  pollToken: async () => devPoll.result,
  mapTokens: (t: RawTokens) => ({ accessToken: String(t.access_token), expiresIn: 300 }),
} as unknown as OAuthAdapter);

beforeEach(() => {
  cbFail = false;
  cbExchange.args = null;
  cbBuild.redirect = null;
  devPoll.result = { ok: false, data: { error: "authorization_pending" } };
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ---------- typed missing-key error ---------- */

describe("MissingKeyMaterialError", () => {
  it("store throws the typed error (instanceof, message unchanged)", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db, OAUTH_ENCRYPTION_KEY: undefined });
    const err = await savePending(env, { provider: "x", mode: "device", deviceCode: "d", ttlSec: 60 }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(MissingKeyMaterialError);
    expect((err as Error).message).toBe("set OAUTH_ENCRYPTION_KEY secret first");
  });

  it("oauthGuard maps the typed error to 503 via instanceof", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db, OAUTH_ENCRYPTION_KEY: undefined });
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/oauth/keytest/complete",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token: "sk-fake-1" }),
        },
        await adminCookie(env),
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: { message: "set OAUTH_ENCRYPTION_KEY secret first" } });
  });
});

/* ---------- auto-callback (public, state-matched) ---------- */

describe("GET /admin/oauth/:prefix/callback (public)", () => {
  async function seedPending(opts: { mode?: "pkce" | "device"; state?: string | null; ttlSec?: number } = {}) {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    await savePending(env, {
      provider: "cbtest",
      mode: opts.mode ?? "pkce",
      state: opts.state === undefined ? "st-1" : opts.state,
      codeVerifier: opts.mode === "device" ? null : "vf-1",
      deviceCode: opts.mode === "device" ? "dc-1" : null,
      ttlSec: opts.ttlSec ?? 600,
    });
    return { env, db };
  }

  it("no admin cookie — state match completes the flow", async () => {
    const { env } = await seedPending();
    const res = await gateway.fetch(
      new Request("https://gw.test/admin/oauth/cbtest/callback?code=abc&state=st-1"),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    const html = await res.text();
    expect(html).toContain("<title>FreeAI Gateway</title>");
    expect(html).toContain("cbtest");
    // engine received the code + the pending verifier/state
    expect(cbExchange.args![1]).toBe("abc");
    expect(cbExchange.args![3]).toBe("vf-1");
    expect(cbExchange.args![4]).toBe("st-1");
    // pending consumed
    expect(await getPending(env, "cbtest")).toBeNull();
  });

  it("state mismatch → 400 HTML", async () => {
    const { env } = await seedPending();
    const res = await gateway.fetch(
      new Request("https://gw.test/admin/oauth/cbtest/callback?code=abc&state=wrong"),
      env,
      ctx,
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid or expired login link");
    expect(await getPending(env, "cbtest")).not.toBeNull(); // mismatch does NOT consume
  });

  it("missing state param → 400", async () => {
    const { env } = await seedPending();
    const res = await gateway.fetch(
      new Request("https://gw.test/admin/oauth/cbtest/callback?code=abc"),
      env,
      ctx,
    );
    expect(res.status).toBe(400);
  });

  it("expired pending row → 400", async () => {
    const { env } = await seedPending({ ttlSec: 0 });
    const res = await gateway.fetch(
      new Request("https://gw.test/admin/oauth/cbtest/callback?code=abc&state=st-1"),
      env,
      ctx,
    );
    expect(res.status).toBe(400);
  });

  it("unknown prefix → 400", async () => {
    const res = await gateway.fetch(
      new Request("https://gw.test/admin/oauth/nope/callback?code=abc&state=st-1"),
      envWith({ DB: stubDb().db }),
      ctx,
    );
    expect(res.status).toBe(400);
  });

  it("device-mode pending row → 400 (route serves pkce only)", async () => {
    const { env } = await seedPending({ mode: "device" });
    const res = await gateway.fetch(
      new Request("https://gw.test/admin/oauth/cbtest/callback?code=abc&state=st-1"),
      env,
      ctx,
    );
    expect(res.status).toBe(400);
  });

  it("single-use on failure — failed exchange still consumes the state", async () => {
    const { env } = await seedPending();
    cbFail = true;
    const first = await gateway.fetch(
      new Request("https://gw.test/admin/oauth/cbtest/callback?code=abc&state=st-1"),
      env,
      ctx,
    );
    expect(first.status).toBe(200); // page, not API — error text on the page
    expect(await first.text()).toContain("upstream said no");
    expect(await getPending(env, "cbtest")).toBeNull();
    const replay = await gateway.fetch(
      new Request("https://gw.test/admin/oauth/cbtest/callback?code=abc&state=st-1"),
      env,
      ctx,
    );
    expect(replay.status).toBe(400);
  });

  it("redirect resolution (builder b3): start and exchange use the IDENTICAL /admin/oauth/:prefix/callback", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    const start = await gateway.fetch(
      adminReq("/admin/api/oauth/cbtest/start", { method: "POST" }, await adminCookie(env)),
      env,
      ctx,
    );
    expect(start.status).toBe(200);
    expect(cbBuild.redirect).toBe("https://gw.test/admin/oauth/cbtest/callback");
    // Now complete via the public callback — the SAME redirect string reaches exchangeToken.
    const started = (await start.json()) as { state: string };
    await gateway.fetch(
      new Request(
        `https://gw.test/admin/oauth/cbtest/callback?code=abc&state=${encodeURIComponent(started.state)}`,
      ),
      env,
      ctx,
    );
    expect(cbExchange.args![2]).toBe("https://gw.test/admin/oauth/cbtest/callback");
  });
});

/* ---------- importToken flag on the adapter list ---------- */

describe("listAdapters importToken flag", () => {
  it("list carries importToken:true for boxtest, false for kilocode", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    const res = await gateway.fetch(adminReq("/admin/api/oauth", {}, await adminCookie(env)), env, ctx);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { providers: Array<{ prefix: string; importToken?: boolean }> };
    const box = body.providers.find((p) => p.prefix === "boxtest");
    const kilo = body.providers.find((p) => p.prefix === "kilocode");
    expect(box).toBeDefined();
    expect(box!.importToken).toBe(true);
    expect(kilo).toBeDefined();
    expect(kilo!.importToken).toBe(false);
  });
});

/* ---------- engine msg/code surfacing ---------- */

describe("device poll msg/code surfacing", () => {
  it("code + msg → 'poll failed (code 500): boom'", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    registerAdapter(msgAdapter({ code: 500, msg: "boom" }));
    await savePending(env, { provider: "msgdev", mode: "device", deviceCode: "dc-1", ttlSec: 600 });
    expect(await poll(env, "msgdev")).toEqual({ status: "error", error: "poll failed (code 500): boom" });
  });

  it("msg only → 'poll failed: boom'", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    registerAdapter(msgAdapter({ msg: "boom" }));
    await savePending(env, { provider: "msgdev", mode: "device", deviceCode: "dc-1", ttlSec: 600 });
    expect(await poll(env, "msgdev")).toEqual({ status: "error", error: "poll failed: boom" });
  });

  it("code only → 'poll failed (code 500)'", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    registerAdapter(msgAdapter({ code: 500 }));
    await savePending(env, { provider: "msgdev", mode: "device", deviceCode: "dc-1", ttlSec: 600 });
    expect(await poll(env, "msgdev")).toEqual({ status: "error", error: "poll failed (code 500)" });
  });

  it("error field keeps priority and legacy shapes are unchanged", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    registerAdapter(msgAdapter({ error: "expired_token", code: 1, msg: "ignored" }));
    await savePending(env, { provider: "msgdev", mode: "device", deviceCode: "dc-1", ttlSec: 600 });
    expect(await poll(env, "msgdev")).toEqual({ status: "error", error: "expired_token" });
  });
});

/* ---------- DOM harness (fresh Window per test, mirrors admin-ui-dom-oauth) ---------- */

type RouteFn = (url: string, init: RequestInit | undefined) => unknown;
type Routes = Record<string, unknown | RouteFn>;

const DEV_EXPIRES = 1_900_000_000_000;

const ui = {
  pollCount: 0,
  pollResult: "pending" as "pending" | "slow_down" | "connected",
  devConnected: false,
};

function domListBody(): unknown {
  const mk = (prefix: string, flowMode: string, importToken = false) => ({
    prefix,
    flowMode,
    connected: prefix === "fakedev" && ui.devConnected,
    expiresAt: ui.devConnected ? DEV_EXPIRES : null,
    accountLabel: ui.devConnected ? "Dev User" : null,
    lastError: null,
    importToken,
  });
  return {
    providers: [
      mk("trae", "paste"),
      mk("cline", "device"),
      mk("boxtest", "device", true),
      mk("fakedev", "device"),
    ],
  };
}

function domRoutes(): Routes {
  return {
    "/admin/api/oauth/fakedev/poll": () => {
      ui.pollCount += 1;
      if (ui.pollResult === "connected") return { status: "connected" };
      if (ui.pollResult === "slow_down") return { status: "pending", error: "slow_down" };
      return { status: "pending" };
    },
    "/admin/api/oauth/fakedev/start": () => ({
      mode: "device",
      user_code: "XY-99",
      verification_uri: "https://verify.example/x",
      verification_uri_complete: "https://verify.example/x",
      expires_in: 300,
      interval: 5,
    }),
    "/admin/api/oauth/fakedev": (_url: string, init: RequestInit | undefined) => {
      if ((init?.method ?? "GET") === "DELETE") return { disconnected: "fakedev" };
      return domListBody();
    },
    "/admin/api/oauth/boxtest/complete": () => ({ error: { message: "boxtest completes through the device flow" } }),
    "/admin/api/oauth": () => domListBody(),
    "/admin/api/me": { authenticated: true },
    "/admin/api/providers": { providers: [] },
    "/admin/api/logs": { logs: [] },
    "/admin/api/stats": { stats: [] },
    "/admin/api/fallbacks": { chains: [] },
  };
}

let fetchCalls: Array<{ url: string; init?: RequestInit }> = [];

function installDomFetch(routes: Routes = domRoutes()): void {
  fetchCalls = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      const path = url.replace(/^https?:\/\/[^/]+/, "");
      fetchCalls.push({ url: path, init });
      for (const [prefix, body] of Object.entries(routes)) {
        if (path.startsWith(prefix)) {
          const payload = typeof body === "function" ? (body as RouteFn)(path, init) : body;
          return new Response(JSON.stringify(payload), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
      }
      return new Response(JSON.stringify({ error: { message: "not found" } }), { status: 404 });
    }),
  );
}

function mountSkeleton(): void {
  document.body.innerHTML = `
  <div id="login-overlay" class="overlay hidden">
    <form id="login-form">
      <input id="login-password" type="password" />
      <p id="login-error" class="error-text hidden"></p>
    </form>
  </div>
  <header id="app-header" class="hidden"><button id="logout-btn" type="button">Log out</button></header>
  <nav id="app-nav" class="hidden">
    <button id="tab-overview" class="tab" aria-controls="panel-overview" aria-selected="true" type="button">Overview</button>
    <button id="tab-logs" class="tab" aria-controls="panel-logs" aria-selected="false" type="button">Logs</button>
    <button id="tab-stats" class="tab" aria-controls="panel-stats" aria-selected="false" type="button">Stats</button>
    <button id="tab-fallbacks" class="tab" aria-controls="panel-fallbacks" aria-selected="false" type="button">Fallbacks</button>
    <button id="tab-playground" class="tab" aria-controls="panel-playground" aria-selected="false" type="button">Playground</button>
  </nav>
  <div id="notice" class="notice hidden"></div>
  <main id="app-main" class="hidden">
    <section id="panel-overview" class="panel">
      <button id="providers-reload" type="button">Reload</button>
      <div id="provider-grid"></div>
      <div class="panel-head">
        <h2>OAuth Providers</h2>
        <button id="oauth-reload" class="btn ghost" type="button">Reload</button>
      </div>
      <div id="oauth-grid" class="oauth-grid"></div>
    </section>
    <section id="panel-logs" class="panel hidden">
      <select id="logs-provider"></select>
      <select id="logs-limit"><option>50</option><option>100</option><option>200</option></select>
      <label><input id="logs-auto" type="checkbox" /> auto</label>
      <button id="logs-reload" type="button">Reload</button>
      <button id="logs-prune" type="button">Prune &gt;30d</button>
      <table id="logs-table"><tbody id="logs-body"></tbody></table>
      <p id="logs-empty" class="hidden"></p>
    </section>
    <section id="panel-stats" class="panel hidden">
      <button id="stats-reload" type="button">Reload</button>
      <table id="stats-table"><tbody id="stats-body"></tbody></table>
      <p id="stats-empty" class="hidden"></p>
    </section>
    <section id="panel-fallbacks" class="panel hidden">
      <button id="chain-add" type="button">Add chain</button>
      <button id="fallbacks-save" type="button">Save chains</button>
      <div id="chains-editor"></div>
      <p id="fallbacks-error" class="hidden"></p>
    </section>
    <section id="panel-playground" class="panel hidden">
      <form id="playground-form">
        <input id="pg-model" type="text" />
        <textarea id="pg-prompt"></textarea>
        <input id="pg-stream" type="checkbox" />
        <button id="pg-run" type="submit">Run</button>
      </form>
      <pre id="pg-response"></pre>
    </section>
  </main>`;
}

function uiCard(prefix: string): HTMLElement {
  return document.querySelector<HTMLElement>(`.oauth-card[data-prefix="${prefix}"]`)!;
}

function uiCalls(method: string, sub: string): Array<{ url: string; init?: RequestInit }> {
  return fetchCalls.filter((c) => c.url.includes(sub) && (c.init?.method ?? "GET") === method);
}

async function flush(): Promise<void> {
  await vi.advanceTimersByTimeAsync(0);
  await vi.advanceTimersByTimeAsync(0);
}

describe("OAuth console carry-overs (DOM)", () => {
  beforeEach(async () => {
    vi.resetModules();
    const win = new Window();
    vi.stubGlobal("document", win.document);
    vi.stubGlobal("Event", win.Event);
    vi.stubGlobal("KeyboardEvent", win.KeyboardEvent);
    ui.pollCount = 0;
    ui.pollResult = "pending";
    ui.devConnected = false;
    mountSkeleton();
    installDomFetch();
    await import("../public/admin/app.js");
    await vi.waitFor(() => {
      expect(document.getElementById("oauth-grid")!.children.length).toBe(4);
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("disconnect stops the device poll chain (liveness bug)", async () => {
    ui.devConnected = true;
    document.getElementById("oauth-reload")!.click();
    await vi.waitFor(() => {
      expect(uiCard("fakedev").querySelector(".oauth-disconnect")).not.toBeNull();
    });
    vi.useFakeTimers();
    uiCard("fakedev").querySelector<HTMLButtonElement>(".oauth-start")!.click();
    await flush();
    expect(ui.pollCount).toBe(1);
    uiCard("fakedev").querySelector<HTMLButtonElement>(".oauth-disconnect")!.click();
    await flush();
    const at = ui.pollCount;
    await vi.advanceTimersByTimeAsync(60000);
    await flush();
    expect(ui.pollCount).toBe(at); // chain stopped
  });

  it("double startDevicePoll keeps a single chain (prior timer cleared)", async () => {
    vi.useFakeTimers();
    uiCard("fakedev").querySelector<HTMLButtonElement>(".oauth-start")!.click();
    await flush();
    uiCard("fakedev").querySelector<HTMLButtonElement>(".oauth-start")!.click();
    await flush();
    const at = ui.pollCount;
    await vi.advanceTimersByTimeAsync(30000);
    await flush();
    // one re-arm per interval — a second live chain would double the count
    expect(ui.pollCount).toBeLessThanOrEqual(at + 7);
  });

  it("slow_down bumps the next delay to interval + 5000", async () => {
    vi.useFakeTimers();
    ui.pollResult = "slow_down";
    uiCard("fakedev").querySelector<HTMLButtonElement>(".oauth-start")!.click();
    await flush();
    expect(ui.pollCount).toBe(1);
    await vi.advanceTimersByTimeAsync(5000); // original interval — must NOT re-arm yet
    expect(ui.pollCount).toBe(1);
    await vi.advanceTimersByTimeAsync(5000); // ≥ interval + 5000 elapsed
    expect(ui.pollCount).toBe(2);
  });

  it("paste-token box: renders only on importToken cards; submit POSTs {token}", async () => {
    expect(uiCard("boxtest").querySelector(".oauth-token-input")).not.toBeNull();
    expect(uiCard("cline").querySelector(".oauth-token-input")).toBeNull();
    expect(uiCard("fakedev").querySelector(".oauth-token-input")).toBeNull();
    // paste cards keep their existing single box (class oauth-paste-input)
    expect(uiCard("trae").querySelector(".oauth-paste-input")).not.toBeNull();
    expect(uiCard("trae").querySelector(".oauth-token-input")).toBeNull();

    const input = uiCard("boxtest").querySelector<HTMLInputElement>(".oauth-token-input")!;
    input.value = "t-1";
    uiCard("boxtest").querySelector<HTMLButtonElement>(".oauth-token-connect")!.click();
    await vi.waitFor(() => {
      expect(uiCalls("POST", "/admin/api/oauth/boxtest/complete")).toHaveLength(1);
    });
    expect(JSON.parse(String(uiCalls("POST", "/admin/api/oauth/boxtest/complete")[0].init?.body))).toEqual({
      token: "t-1",
    });
  });
});

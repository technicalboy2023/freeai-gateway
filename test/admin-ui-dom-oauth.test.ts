/// <reference lib="dom" />
/**
 * DOM-level tests for the admin console OAuth UI (Task 12).
 * Mirrors the fresh-Window happy-dom harness from admin-ui-dom.test.ts, with
 * two additions: function-valued routes (stateful device-poll sequences:
 * pending → connected) and oauth subroutes registered BEFORE the
 * "/admin/api/oauth" catch-all — the matcher is startsWith in insertion order.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Window } from "happy-dom";

type RouteFn = (url: string, init: RequestInit | undefined) => unknown;
type Routes = Record<string, unknown | RouteFn>;

const PASTED_TOKEN = "sk-test-token-123";
const DEV_EXPIRES = 1_900_000_000_000; // year 2033

/** Mutable OAuth console state the route functions read/write. */
const oauth = {
  connected: {} as Record<string, { accountLabel: string | null; expiresAt: number | null }>,
  errors: {} as Record<string, string | null>,
  pollCount: 0,
  pollOutcome: "pending" as "pending" | "connected" | "error",
};

function listBody(): unknown {
  const mk = (prefix: string, flowMode: string, extra: Record<string, unknown> = {}) => ({
    prefix,
    flowMode,
    connected: prefix in oauth.connected,
    expiresAt: oauth.connected[prefix]?.expiresAt ?? null,
    accountLabel: oauth.connected[prefix]?.accountLabel ?? null,
    lastError: oauth.errors[prefix] ?? null,
    ...extra,
  });
  return {
    providers: [
      mk("fakepaste", "paste", { instructions: "Paste it." }),
      mk("fakecode", "paste-code"),
      mk("fakedev", "device"),
    ],
  };
}

function oauthRoutes(): Routes {
  return {
    // Specific oauth subroutes FIRST — the matcher is startsWith in insertion
    // order, so the "/admin/api/oauth" catch-all must come last.
    "/admin/api/oauth/fakepaste/complete": (_url: string, init: RequestInit | undefined) => {
      const body = JSON.parse(String(init?.body ?? "{}")) as { token?: string };
      if (body.token !== PASTED_TOKEN) return { error: { message: "bad token" } };
      oauth.connected.fakepaste = { accountLabel: "Paste User", expiresAt: DEV_EXPIRES };
      return { connected: true, accountLabel: "Paste User" };
    },
    "/admin/api/oauth/fakecode/start": () => ({
      mode: "paste-code",
      authUrl: "https://auth.example/login?client=1",
      state: "st-1",
    }),
    "/admin/api/oauth/fakecode/complete": (_url: string, init: RequestInit | undefined) => {
      const body = JSON.parse(String(init?.body ?? "{}")) as { code?: string };
      if (body.code !== "auth-code-9") return { error: { message: "bad code" } };
      oauth.connected.fakecode = { accountLabel: "Code User", expiresAt: DEV_EXPIRES };
      return { connected: true, accountLabel: "Code User" };
    },
    "/admin/api/oauth/fakedev/start": () => ({
      mode: "device",
      user_code: "XY-99",
      verification_uri: "https://verify.example/x",
      verification_uri_complete: "https://verify.example/x",
      expires_in: 300,
      interval: 5,
    }),
    "/admin/api/oauth/fakedev/poll": () => {
      oauth.pollCount += 1;
      if (oauth.pollOutcome === "connected") {
        oauth.connected.fakedev = { accountLabel: "Dev User", expiresAt: DEV_EXPIRES };
        return { status: "connected" };
      }
      if (oauth.pollOutcome === "error") {
        oauth.errors.fakedev = "access_denied";
        return { status: "error", error: "access_denied" };
      }
      return { status: "pending" };
    },
    "/admin/api/oauth/fakedev": (url: string, init: RequestInit | undefined) => {
      if ((init?.method ?? "GET") === "DELETE") {
        delete oauth.connected.fakedev;
        return { disconnected: "fakedev" };
      }
      return listBody();
    },
    "/admin/api/oauth": () => listBody(),
    // Plain routes (static JSON bodies)
    "/admin/api/me": { authenticated: true },
    "/admin/api/providers": { providers: [] },
    "/admin/api/logs": { logs: [] },
    "/admin/api/stats": { stats: [] },
    "/admin/api/fallbacks": { chains: [] },
  };
}

let fetchCalls: Array<{ url: string; init?: RequestInit }> = [];

function installFetch(routes: Routes = oauthRoutes()): void {
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
          // The real admin API answers 200 for poll "error" statuses — the
          // harness must not guess status codes from body shape.
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

/** index.html element skeleton (ids app.js touches at import time). */
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

function card(prefix: string): HTMLElement {
  return document.querySelector<HTMLElement>(`.oauth-card[data-prefix="${prefix}"]`)!;
}

function calls(method: string, sub: string): Array<{ url: string; init?: RequestInit }> {
  return fetchCalls.filter(
    (c) => c.url.includes(sub) && (c.init?.method ?? "GET") === method,
  );
}

function bodyOf(call: { init?: RequestInit }): Record<string, unknown> {
  return JSON.parse(String(call.init?.body ?? "{}")) as Record<string, unknown>;
}

/** Drain pending microtasks/timers while fake timers are active. */
async function flush(): Promise<void> {
  await vi.advanceTimersByTimeAsync(0);
  await vi.advanceTimersByTimeAsync(0);
}

beforeEach(async () => {
  vi.resetModules();
  // Fresh Window per test: zero lingering listeners, exact event semantics.
  const win = new Window();
  vi.stubGlobal("document", win.document);
  vi.stubGlobal("Event", win.Event);
  vi.stubGlobal("KeyboardEvent", win.KeyboardEvent);
  oauth.connected = {};
  oauth.errors = {};
  oauth.pollCount = 0;
  oauth.pollOutcome = "pending";
  mountSkeleton();
  installFetch();
  await import("../public/admin/app.js");
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("OAuth grid rendering", () => {
  it("renders one card per adapter with flow badge + status line", async () => {
    await vi.waitFor(() => {
      expect(document.getElementById("oauth-grid")!.children.length).toBe(3);
    });
    // State set after boot → the Reload button re-fetches the list.
    oauth.connected.fakedev = { accountLabel: "Dev User", expiresAt: DEV_EXPIRES };
    document.getElementById("oauth-reload")!.click();
    await vi.waitFor(() => {
      expect(card("fakedev").querySelector(".oauth-status")!.textContent).toContain("connected · expires");
    });
    expect(card("fakepaste").querySelector(".flow-badge")!.textContent).toBe("paste");
    expect(card("fakecode").querySelector(".flow-badge")!.textContent).toBe("paste-code");
    expect(card("fakedev").querySelector(".flow-badge")!.textContent).toBe("device");
    expect(card("fakepaste").querySelector(".oauth-status")!.textContent).toContain("not connected");
    expect(card("fakecode").querySelector(".oauth-status")!.textContent).toContain("not connected");
    expect(card("fakepaste").textContent).toContain("Paste it.");
    // Only connected cards offer disconnect.
    expect(card("fakedev").querySelector(".oauth-disconnect")).not.toBeNull();
    expect(card("fakepaste").querySelector(".oauth-disconnect")).toBeNull();
  });

  it("surfaces last error on the card", async () => {
    await vi.waitFor(() => {
      expect(document.getElementById("oauth-grid")!.children.length).toBe(3);
    });
    oauth.errors.fakepaste = "refresh failed (400)";
    document.getElementById("oauth-reload")!.click();
    await vi.waitFor(() => {
      expect(card("fakepaste").querySelector(".oauth-status")!.textContent).toContain(
        "last error: refresh failed (400)",
      );
    });
  });

  it("connected row with lastError still surfaces the reconnect hint (corrupt-token state)", async () => {
    await vi.waitFor(() => {
      expect(document.getElementById("oauth-grid")!.children.length).toBe(3);
    });
    oauth.connected.fakepaste = { accountLabel: "Paste User", expiresAt: DEV_EXPIRES };
    oauth.errors.fakepaste = "token decrypt failed — reconnect required";
    document.getElementById("oauth-reload")!.click();
    await vi.waitFor(() => {
      const status = card("fakepaste").querySelector(".oauth-status")!.textContent;
      expect(status).toContain("connected · expires");
      expect(status).toContain("reconnect required: token decrypt failed");
    });
  });
});

describe("paste flow", () => {
  it("connect posts {token} then reloads; token material never rendered", async () => {
    await vi.waitFor(() => {
      expect(document.getElementById("oauth-grid")!.children.length).toBe(3);
    });
    const input = card("fakepaste").querySelector<HTMLInputElement>(".oauth-paste-input")!;
    input.value = PASTED_TOKEN;
    card("fakepaste").querySelector<HTMLButtonElement>(".oauth-connect")!.click();
    await vi.waitFor(() => {
      expect(calls("POST", "/admin/api/oauth/fakepaste/complete")).toHaveLength(1);
    });
    expect(bodyOf(calls("POST", "/admin/api/oauth/fakepaste/complete")[0])).toEqual({
      token: PASTED_TOKEN,
    });
    await vi.waitFor(() => {
      expect(card("fakepaste").querySelector(".oauth-status")!.textContent).toContain("connected · expires");
    });
    expect(document.body.textContent).not.toContain(PASTED_TOKEN);
  });
});

describe("paste-code flow", () => {
  it("start shows the auth link; complete posts {code}", async () => {
    await vi.waitFor(() => {
      expect(document.getElementById("oauth-grid")!.children.length).toBe(3);
    });
    card("fakecode").querySelector<HTMLButtonElement>(".oauth-start")!.click();
    await vi.waitFor(() => {
      expect(calls("POST", "/admin/api/oauth/fakecode/start")).toHaveLength(1);
    });
    const link = await vi.waitFor(() => {
      const el = card("fakecode").querySelector<HTMLAnchorElement>(".oauth-auth-link");
      expect(el).not.toBeNull();
      return el!;
    });
    expect(link.href).toBe("https://auth.example/login?client=1");
    const codeInput = card("fakecode").querySelector<HTMLInputElement>(".oauth-code-input")!;
    codeInput.value = "auth-code-9";
    card("fakecode").querySelector<HTMLButtonElement>(".oauth-complete")!.click();
    await vi.waitFor(() => {
      expect(calls("POST", "/admin/api/oauth/fakecode/complete")).toHaveLength(1);
    });
    expect(bodyOf(calls("POST", "/admin/api/oauth/fakecode/complete")[0])).toEqual({
      code: "auth-code-9",
    });
    await vi.waitFor(() => {
      expect(card("fakecode").querySelector(".oauth-status")!.textContent).toContain("connected · expires");
    });
  });
});

describe("device flow", () => {
  it("start shows user_code + verify link, polls until connected, then stops", async () => {
    await vi.waitFor(() => {
      expect(document.getElementById("oauth-grid")!.children.length).toBe(3);
    });
    vi.useFakeTimers();
    card("fakedev").querySelector<HTMLButtonElement>(".oauth-start")!.click();
    await flush();
    expect(calls("POST", "/admin/api/oauth/fakedev/start")).toHaveLength(1);
    expect(card("fakedev").querySelector(".oauth-user-code")!.textContent).toContain("XY-99");
    expect(card("fakedev").querySelector<HTMLAnchorElement>(".oauth-auth-link")!.href).toBe(
      "https://verify.example/x",
    );
    expect(oauth.pollCount).toBe(1); // first poll fires immediately (pending)
    oauth.pollOutcome = "connected"; // user approves on the site
    await vi.advanceTimersByTimeAsync(5000); // interval elapsed → second poll → connected
    await flush();
    expect(oauth.pollCount).toBe(2);
    expect(card("fakedev").querySelector(".oauth-status")!.textContent).toContain("connected · expires");
    await vi.advanceTimersByTimeAsync(30000);
    expect(oauth.pollCount).toBe(2); // loop stopped after connected
  });

  it("poll error stops the loop and surfaces the error", async () => {
    await vi.waitFor(() => {
      expect(document.getElementById("oauth-grid")!.children.length).toBe(3);
    });
    vi.useFakeTimers();
    oauth.pollOutcome = "error";
    card("fakedev").querySelector<HTMLButtonElement>(".oauth-start")!.click();
    await flush();
    expect(oauth.pollCount).toBe(1);
    expect(document.getElementById("notice")!.textContent).toContain("access_denied");
    await vi.advanceTimersByTimeAsync(30000);
    expect(oauth.pollCount).toBe(1); // no further polls after error
  });

  it("leaving the overview tab stops the device poll timer", async () => {
    await vi.waitFor(() => {
      expect(document.getElementById("oauth-grid")!.children.length).toBe(3);
    });
    vi.useFakeTimers();
    card("fakedev").querySelector<HTMLButtonElement>(".oauth-start")!.click();
    await flush();
    expect(oauth.pollCount).toBe(1);
    document.getElementById("tab-logs")!.click();
    await flush();
    const at = oauth.pollCount;
    await vi.advanceTimersByTimeAsync(60000);
    expect(oauth.pollCount).toBe(at); // timer cleared on tab switch
  });

  it("disconnect fires DELETE and reloads the grid", async () => {
    await vi.waitFor(() => {
      expect(document.getElementById("oauth-grid")!.children.length).toBe(3);
    });
    oauth.connected.fakedev = { accountLabel: "Dev User", expiresAt: DEV_EXPIRES };
    document.getElementById("oauth-reload")!.click();
    await vi.waitFor(() => {
      expect(card("fakedev").querySelector(".oauth-status")!.textContent).toContain("connected · expires");
    });
    card("fakedev").querySelector<HTMLButtonElement>(".oauth-disconnect")!.click();
    await vi.waitFor(() => {
      expect(calls("DELETE", "/admin/api/oauth/fakedev")).toHaveLength(1);
    });
    await vi.waitFor(() => {
      expect(card("fakedev").querySelector(".oauth-status")!.textContent).toContain("not connected");
    });
  });
});

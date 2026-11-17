/// <reference lib="dom" />
/**
 * DOM-level tests for the admin console SPA (public/admin/app.js).
 * Each test gets a FRESH happy-dom Window (stubbed over the node globals) so
 * document-level listeners registered by the SPA never leak across tests —
 * re-importing the module against a shared document would accumulate
 * listeners and cascade every keydown N times.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Window } from "happy-dom";

const PROVIDERS = [
  { prefix: "groq", enabled: true, keyConfigured: true, freeModels: ["m1"] },
  { prefix: "nvidia", enabled: false, keyConfigured: false, freeModels: [] },
];
const LOG_ROWS = [
  {
    ts: 1_700_000_000_000,
    provider: "groq",
    model: "m1",
    status: 502,
    latency_ms: 12,
    stream: 0,
    chain: null,
    attempt: null,
    error: "network-error:groq",
  },
];

let fetchCalls: Array<{ url: string; init?: RequestInit }> = [];

function defaultRoutes(): Record<string, unknown> {
  return {
    "/admin/api/me": { authenticated: true },
    "/admin/api/providers": { providers: PROVIDERS },
    "/admin/api/logs": { logs: LOG_ROWS },
    "/admin/api/stats": { stats: [] },
    "/admin/api/fallbacks": { chains: [{ name: "fast", providers: ["groq"] }] },
    "/admin/api/oauth": { providers: [] },
  };
}

function installFetch(routes: Record<string, unknown> = defaultRoutes()): void {
  fetchCalls = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      fetchCalls.push({ url, init });
      const path = url.replace(/^https?:\/\/[^/]+/, "");
      for (const [prefix, body] of Object.entries(routes)) {
        if (path.startsWith(prefix)) {
          return new Response(JSON.stringify(body), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
      }
      return new Response(JSON.stringify({ error: { message: "not found" } }), {
        status: 404,
      });
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

async function importApp(): Promise<void> {
  await import("../public/admin/app.js");
}

beforeEach(async () => {
  vi.resetModules();
  // Fresh Window per test: zero lingering listeners, exact event semantics.
  const win = new Window();
  vi.stubGlobal("document", win.document);
  vi.stubGlobal("Event", win.Event);
  vi.stubGlobal("KeyboardEvent", win.KeyboardEvent);
  mountSkeleton();
  installFetch();
  await importApp();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("SPA render behavior (DOM)", () => {
  it("renders provider cards from the API", async () => {
    await vi.waitFor(() => {
      expect(document.getElementById("provider-grid")!.children.length).toBe(2);
    });
    const groq = document.querySelector<HTMLElement>('[data-prefix="groq"]')!;
    expect(groq.textContent).toContain("groq");
    expect(groq.querySelector<HTMLInputElement>(".provider-toggle")!.checked).toBe(true);
    const nvidia = document.querySelector<HTMLElement>('[data-prefix="nvidia"]')!;
    expect(nvidia.querySelector<HTMLInputElement>(".provider-toggle")!.checked).toBe(false);
  });

  it("populates the Logs provider filter after providers load", async () => {
    await vi.waitFor(() => {
      const select = document.getElementById("logs-provider")!;
      const options = Array.from(select.querySelectorAll("option")).map((o) =>
        o.getAttribute("value"),
      );
      expect(options).toEqual(["all", "groq", "nvidia"]);
    });
  });

  it("renders the row error in the Error column", async () => {
    await vi.waitFor(() => {
      const firstRow = document.querySelector("#logs-body tr")!;
      expect(firstRow).not.toBeNull();
      const tds = firstRow.querySelectorAll("td");
      expect(tds[tds.length - 1].textContent).toBe("network-error:groq");
      // Status cell shows the status only — error text lives in its column.
      expect(tds[3].textContent).toBe("502");
    });
  });

  it("ArrowRight/Left do NOT hijack text inputs (tab unchanged)", () => {
    const prompt = document.getElementById("pg-prompt") as HTMLTextAreaElement;
    prompt.focus();
    prompt.dispatchEvent(
      new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }),
    );
    expect(
      document.getElementById("tab-logs")!.getAttribute("aria-selected"),
    ).toBe("false");

    prompt.dispatchEvent(
      new KeyboardEvent("keydown", { key: "ArrowLeft", bubbles: true }),
    );
    expect(
      document.getElementById("tab-playground")!.getAttribute("aria-selected"),
    ).toBe("false");
  });

  it("ArrowRight still switches tabs when focus is not in a text field", () => {
    document.body.dispatchEvent(
      new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }),
    );
    expect(
      document.getElementById("tab-logs")!.getAttribute("aria-selected"),
    ).toBe("true");
  });

  it("chain name edits survive chip operations (input event syncs state)", async () => {
    await vi.waitFor(() => {
      expect(document.querySelector(".chain-row")).not.toBeNull();
    });
    const nameInput = document.querySelector<HTMLInputElement>(".chain-name-input")!;
    nameInput.value = "superfast";
    nameInput.dispatchEvent(new Event("input", { bubbles: true }));
    // A chip operation re-renders the editor.
    const addBtn = document.querySelector<HTMLButtonElement>(".chain-add-btn")!;
    addBtn.click();
    const after = document.querySelector<HTMLInputElement>(".chain-name-input")!;
    expect(after.value).toBe("superfast");
  });

  it("leaving the Logs tab stops the auto-refresh timer", async () => {
    await vi.waitFor(() => {
      expect(document.getElementById("provider-grid")!.children.length).toBeGreaterThan(0);
    });
    vi.useFakeTimers();
    const logsCount = () =>
      fetchCalls.filter((c) => c.url.includes("/admin/api/logs")).length;
    const auto = document.getElementById("logs-auto") as HTMLInputElement;
    auto.click(); // enable 5s auto-refresh
    const before = logsCount();
    await vi.advanceTimersByTimeAsync(5000);
    expect(logsCount()).toBeGreaterThan(before);

    document.getElementById("tab-stats")!.click(); // leave Logs
    const atLeave = logsCount();
    await vi.advanceTimersByTimeAsync(20000);
    expect(logsCount()).toBe(atLeave);
  });

  it("login (401) stops the auto-refresh timer", async () => {
    await vi.waitFor(() => {
      expect(document.getElementById("provider-grid")!.children.length).toBeGreaterThan(0);
    });
    vi.useFakeTimers();
    const logsCount = () =>
      fetchCalls.filter((c) => c.url.includes("/admin/api/logs")).length;
    const auto = document.getElementById("logs-auto") as HTMLInputElement;
    auto.click();
    const before = logsCount();
    await vi.advanceTimersByTimeAsync(5000);
    expect(logsCount()).toBeGreaterThan(before);

    // Next logs poll returns 401 → SPA must stop the timer, not hammer 401s.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        fetchCalls.push({ url: String(input) });
        return new Response(JSON.stringify({ error: { message: "Unauthorized" } }), {
          status: 401,
        });
      }),
    );
    await vi.advanceTimersByTimeAsync(5000);
    const stopped = logsCount();
    await vi.advanceTimersByTimeAsync(20000);
    // Only the one 401-triggering poll after the stub swap — no further polls.
    expect(logsCount()).toBe(stopped);
  });

  it("prune button POSTs /admin/api/logs/prune with olderThanDays", async () => {
    await vi.waitFor(() => {
      expect(document.getElementById("provider-grid")!.children.length).toBeGreaterThan(0);
    });
    const pruneBtn = document.getElementById("logs-prune") as HTMLButtonElement;
    expect(pruneBtn).not.toBeNull();
    pruneBtn.click();
    await vi.waitFor(() => {
      const call = fetchCalls.find((c) => c.url.includes("/admin/api/logs/prune"));
      expect(call).toBeDefined();
      const init = call!.init as RequestInit;
      expect(init.method).toBe("POST");
      expect(JSON.parse(String(init.body))).toEqual({ olderThanDays: 30 });
    });
  });
});

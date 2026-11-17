import { describe, expect, it } from "vitest";
import { resolve, list } from "../src/providers";

describe("provider registry", () => {
  it("resolves groq/llama-3.3-70b to groq config", () => {
    const r = resolve("groq/llama-3.3-70b");
    expect(r).toEqual({
      prefix: "groq",
      baseURL: "https://api.groq.com/openai/v1",
      auth: "bearer",
      keySecret: "GROQ_API_KEY",
      model: "llama-3.3-70b",
    });
  });

  it("resolves gemini/gemini-3.5-flash to google openai-compat base", () => {
    const r = resolve("gemini/gemini-3.5-flash")!;
    expect(r.baseURL).toBe("https://generativelanguage.googleapis.com/v1beta/openai");
    expect(r.auth).toBe("bearer");
    expect(r.keySecret).toBe("GEMINI_API_KEY");
    expect(r.model).toBe("gemini-3.5-flash");
  });

  it("resolves openrouter/deepseek-r1:free", () => {
    const r = resolve("openrouter/deepseek-r1:free")!;
    expect(r.baseURL).toBe("https://openrouter.ai/api/v1");
    expect(r.keySecret).toBe("OPENROUTER_API_KEY");
  });

  it("resolves nvidia/deepseek-v4.1-flash", () => {
    const r = resolve("nvidia/deepseek-v4.1-flash")!;
    expect(r.baseURL).toBe("https://integrate.api.nvidia.com/v1");
    expect(r.keySecret).toBe("NVIDIA_API_KEY");
  });

  it("resolves mistral/mistral-large-latest", () => {
    const r = resolve("mistral/mistral-large-latest")!;
    expect(r.baseURL).toBe("https://api.mistral.ai/v1");
    expect(r.keySecret).toBe("MISTRAL_API_KEY");
  });

  it("resolves zen/gpt-5.5", () => {
    const r = resolve("zen/gpt-5.5")!;
    expect(r.baseURL).toBe("https://opencode.ai/zen/v1");
    expect(r.keySecret).toBe("ZEN_API_KEY");
  });

  it("resolves openai/gpt-4o", () => {
    const r = resolve("openai/gpt-4o")!;
    expect(r.baseURL).toBe("https://api.openai.com/v1");
    expect(r.keySecret).toBe("OPENAI_API_KEY");
  });

  it("resolves anthropic/claude-sonnet-4 as anthropic-style auth", () => {
    const r = resolve("anthropic/claude-sonnet-4")!;
    expect(r.baseURL).toBe("https://api.anthropic.com/v1");
    expect(r.auth).toBe("anthropic");
    expect(r.keySecret).toBe("ANTHROPIC_API_KEY");
  });

  it("splits on first slash so nested model ids stay intact", () => {
    const r = resolve("nvidia/deepseek-ai/deepseek-r1")!;
    expect(r.prefix).toBe("nvidia");
    expect(r.model).toBe("deepseek-ai/deepseek-r1");
  });

  it("returns null for unknown prefix or malformed id", () => {
    expect(resolve("foo/bar")).toBeNull();
    expect(resolve("groq/")).toBeNull();
    expect(resolve("justamodel")).toBeNull();
  });

  it("list() returns all 8 phase-A providers with prefixes and aliases", () => {
    const providers = list();
    expect(providers).toHaveLength(8);
    expect(providers.map((p) => p.prefix)).toEqual([
      "groq",
      "gemini",
      "openrouter",
      "nvidia",
      "mistral",
      "zen",
      "openai",
      "anthropic",
    ]);
    for (const p of providers) {
      expect(p.baseURL).toMatch(/^https:\/\//);
      expect(p.keySecret).toMatch(/_API_KEY$/);
      expect(p.freeModels.length).toBeGreaterThan(0);
    }
  });
});

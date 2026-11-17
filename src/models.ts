import type { Env } from "./env";
import { list } from "./providers";
import { jsonResponse } from "./http";
import { readEnabledMap } from "./config";

/**
 * GET /v1/models — provider-prefixed model list. When a DB binding exists,
 * disabled providers are filtered out (fail-open without D1: everything is
 * advertised, matching Phase A behavior).
 */
export async function handleModels(env?: Env): Promise<Response> {
  let enabled: Record<string, boolean> = {};
  if (env?.DB) {
    enabled = await readEnabledMap(env);
  }
  const data = list()
    .filter((p) => enabled[p.prefix] !== false)
    .flatMap((p) =>
      p.freeModels.map((model) => ({
        id: `${p.prefix}/${model}`,
        object: "model",
        owned_by: p.prefix,
      })),
    );
  return jsonResponse({ object: "list", data });
}

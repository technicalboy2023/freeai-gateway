/**
 * Request logging to D1 (request_logs table). Global Constraint: logging must
 * NEVER break proxy traffic — write failures are swallowed, missing DB binding
 * is a no-op, and writes are fire-and-forget via ctx.waitUntil.
 */
export interface LogEntry {
  ts: number;
  provider: string;
  model: string;
  status: number;
  latencyMs?: number | null;
  stream?: boolean;
  /** Fallback chain name (null for direct provider calls). */
  chain?: string | null;
  /** 1-based position within the chain (null for direct calls). */
  attempt?: number | null;
  /** Attempt error detail (missing-key, network-error, unknown-provider). */
  error?: string | null;
}

export async function logRequest(
  db: D1Database | undefined,
  entry: LogEntry,
): Promise<void> {
  if (!db) return;
  try {
    await db
      .prepare(
        "INSERT INTO request_logs (ts, provider, model, status, latency_ms, stream, chain, attempt, error) " +
          "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
      )
      .bind(
        entry.ts,
        entry.provider,
        entry.model,
        entry.status,
        entry.latencyMs ?? null,
        entry.stream ? 1 : 0,
        entry.chain ?? null,
        entry.attempt ?? null,
        entry.error ?? null,
      )
      .run();
  } catch {
    // D1 down/misconfigured → drop the log row, never the request.
  }
}

/** Fire-and-forget wrapper: schedules the write, skipping when there is no DB. */
export function fireLog(
  ctx: ExecutionContext | undefined,
  db: D1Database | undefined,
  entry: LogEntry,
): void {
  if (!db) return;
  ctx?.waitUntil(logRequest(db, entry));
}

/**
 * Typed OAuth store errors (Wave B Plan 2 carry-overs). Kept in its own
 * module so both store.ts and admin/oauth.ts can import it without a
 * forward.ts cycle (builder b7).
 */

/** Thrown when OAUTH_ENCRYPTION_KEY is missing/unusable — 503, not 400. */
export class MissingKeyMaterialError extends Error {
  constructor() {
    super("set OAUTH_ENCRYPTION_KEY secret first");
    this.name = "MissingKeyMaterialError";
  }
}

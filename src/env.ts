export interface Env {
  GATEWAY_KEY?: string;
  GROQ_API_KEY?: string;
  GEMINI_API_KEY?: string;
  OPENROUTER_API_KEY?: string;
  NVIDIA_API_KEY?: string;
  MISTRAL_API_KEY?: string;
  ZEN_API_KEY?: string;
  OPENAI_API_KEY?: string;
  ANTHROPIC_API_KEY?: string;
  FALLBACK_CHAINS?: string;
  ADMIN_PASSWORD?: string;
  /** AES key (base64url, 32 bytes) encrypting OAuth tokens in D1 (Wave B). */
  OAUTH_ENCRYPTION_KEY?: string;
  /** D1 database binding (Wave D admin console). Absent in Phase-A-only unit tests. */
  DB?: D1Database;
  /** Static assets binding (console SPA). Minimal structural type: stub-friendly. */
  ASSETS?: { fetch(request: Request): Promise<Response> };
}

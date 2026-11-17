export function jsonResponse(
  data: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json",
      // Dynamic API responses: never cache (auth state, toggles, logs).
      "cache-control": "no-store",
      ...headers,
    },
  });
}

export const CORS_HEADERS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "Authorization, Content-Type, Anthropic-Beta",
  "access-control-max-age": "86400",
};

export function withCors(response: Response): Response {
  const next = new Response(response.body, response);
  for (const [key, value] of Object.entries(CORS_HEADERS)) {
    next.headers.set(key, value);
  }
  return next;
}

export function optionsPreflight(): Response {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

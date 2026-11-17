-- FreeAI Gateway: login brute-force throttle (review fix pass)
-- Failed /admin/api/login attempts per client IP; 5 wrong → 15-min lockout.
-- Fail-open: this table missing or D1 down never blocks a login.
CREATE TABLE IF NOT EXISTS login_attempts (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  until INTEGER NOT NULL
);

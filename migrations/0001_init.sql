-- FreeAI Gateway: Wave D admin console tables
CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS request_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  status INTEGER NOT NULL,
  latency_ms INTEGER,
  stream INTEGER DEFAULT 0,
  chain TEXT,
  attempt INTEGER,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON request_logs (ts DESC);
CREATE INDEX IF NOT EXISTS idx_logs_provider ON request_logs (provider);

-- Wave B Plan 2: provider-specific pending extras (gheUrl, kimi deviceId, ...)
-- threaded start → poll → mapTokens. Encrypted with the same enc:v1: TEXT
-- codec as the other sensitive pending columns (Task 1 RF-1).
ALTER TABLE oauth_pending ADD COLUMN extra TEXT;

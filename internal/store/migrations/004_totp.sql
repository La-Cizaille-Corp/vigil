-- Optional TOTP second factor (RFC 6238).
ALTER TABLE users ADD COLUMN totp_secret    TEXT    NOT NULL DEFAULT ''; -- active secret, '' = disabled
ALTER TABLE users ADD COLUMN totp_pending   TEXT    NOT NULL DEFAULT ''; -- secret awaiting confirmation
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;  -- last accepted step (anti-replay)

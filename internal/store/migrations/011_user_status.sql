-- Accounts are disabled rather than deleted, so that the audit log and the
-- triage history keep the name of whoever acted. '' = active.
ALTER TABLE users ADD COLUMN disabled_at TEXT NOT NULL DEFAULT '';

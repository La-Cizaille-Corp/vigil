-- A component that disappears from a new SBOM of its project is retired
-- rather than deleted, so that its triage history survives; it comes back
-- as it was if a later SBOM lists it again. '' = active.
ALTER TABLE assets ADD COLUMN retired_at TEXT NOT NULL DEFAULT '';

-- Known vulnerabilities published before the tracked period, counted at the
-- last check: shown so that "no vulnerability" is not read as "no known flaw".
ALTER TABLE assets ADD COLUMN older_vulns INTEGER NOT NULL DEFAULT 0;

-- How a CPE-only asset is tracked in the NVD (see nvd.Modes).
ALTER TABLE assets ADD COLUMN cpe_mode TEXT NOT NULL DEFAULT ''; -- '' = exact version, recent, all, from
ALTER TABLE assets ADD COLUMN cpe_from TEXT NOT NULL DEFAULT ''; -- first tracked version for mode "from"

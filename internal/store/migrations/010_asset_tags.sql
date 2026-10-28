-- Free tags on assets (team, environment, site...), stored like CTI tags:
-- ",prod,web," so that LIKE '%,prod,%' matches exactly one tag.
ALTER TABLE assets ADD COLUMN tags TEXT NOT NULL DEFAULT '';

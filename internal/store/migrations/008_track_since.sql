-- Tracked period of an asset: vulnerabilities published before track_since
-- ('YYYY-MM-DD') are not reported, unless exploited (KEV). '' = whole history.
ALTER TABLE assets ADD COLUMN track_since TEXT NOT NULL DEFAULT '';

-- The former "recent" NVD mode was a sliding 120-day window: findings aged
-- out of it and were auto-resolved. It becomes "every version of the product"
-- with a fixed start, 120 days before the asset was added.
UPDATE assets SET cpe_mode = 'all', track_since = date(created_at, '-120 days') WHERE cpe_mode = 'recent';

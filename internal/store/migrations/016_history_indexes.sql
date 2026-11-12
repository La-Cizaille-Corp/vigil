-- Indexes found missing by the code audit of 0.4.2 (D4). The history of a
-- finding was read by scanning every event of every finding: on its page, in
-- the dismissal rules at each synchronisation, and for each finding deleted
-- with its asset.
CREATE INDEX finding_events_finding ON finding_events (finding_id);
-- The findings a dismissal rule sets aside were counted by scanning every
-- finding, for each rule. Not a partial index (WHERE dismissed_by <> 0): only
-- the queries repeating that condition would use it.
CREATE INDEX findings_dismissed_by ON findings (dismissed_by);

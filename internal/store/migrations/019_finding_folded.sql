-- One finding per CVE (A80): a finding folded into others leaves the lists,
-- counts, alerts, digests and exports, and keeps its triage and its history.
-- -1: a grouped advisory (USN, DSA...) whose CVEs have their own advisories
-- for the asset; otherwise the id of the finding kept for the same CVE (GHSA
-- and GO). 0 = shown. Rows are folded by the synchronisation, which alone
-- sees the advisories reported outside the tracked period.
ALTER TABLE findings ADD COLUMN folded_into INTEGER NOT NULL DEFAULT 0;

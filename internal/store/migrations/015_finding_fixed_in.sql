-- The versions fixing a finding for its asset, as the stored advisory tells
-- them at the last sync; empty when it names none. Filled from the next sync.
ALTER TABLE findings ADD COLUMN fixed_in TEXT NOT NULL DEFAULT '';

package tracking

import "github.com/La-Cizaille-Corp/vigil/internal/store"

// FixedIn is fixedInAny for one advisory, for the tests of the package: no
// code outside it asks for the versions fixing a finding, kept with it at the
// synchronisation (A64).
func FixedIn(raw string, a store.Asset) string { return fixedInAny(a, raw) }

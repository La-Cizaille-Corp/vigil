package auth

import (
	"os"
	"runtime"
	"testing"
)

// allocatedAtLoad is the memory allocated once the package is loaded, before
// any test runs.
var allocatedAtLoad uint64

func TestMain(m *testing.M) {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	allocatedAtLoad = stats.TotalAlloc
	os.Exit(m.Run())
}

// Loading the package hashes no password: each argon2 hash takes 64 MiB,
// which every command of vigil would pay at start (the timing dummy is made
// at its first use, see dummyHash).
func TestNothingHashedAtLoad(t *testing.T) {
	if allocatedAtLoad >= argonMemory<<10 {
		t.Errorf("%d MiB allocated at load", allocatedAtLoad>>20)
	}
}

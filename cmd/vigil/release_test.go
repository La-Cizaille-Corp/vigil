package main

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Docker image carries every licence file of the release archives
// (.goreleaser.yaml): Vigil's, and those of what the binary embeds. The CI
// checks that the image built does hold them.
func TestImageCarriesArchiveLicences(t *testing.T) {
	archives, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	var copied []string // what COPY takes from the build context
	for _, line := range strings.Split(string(dockerfile), "\n") {
		if f := strings.Fields(line); len(f) > 2 && f[0] == "COPY" && !strings.HasPrefix(f[1], "--") {
			copied = append(copied, f[1:len(f)-1]...)
		}
	}
	licences := regexp.MustCompile(`(?m)^\s*-\s*(?:src:\s*)?(\S*LICENSE\S*)\s*$`).FindAllStringSubmatch(string(archives), -1)
	if len(licences) < 2 {
		t.Fatalf("licences of the archives: %q", licences)
	}
	for _, l := range licences {
		if !slices.Contains(copied, l[1]) {
			t.Errorf("%s is in the release archives, not in the image (COPY %q)", l[1], copied)
		}
	}
}

package sbom

import (
	"strings"
	"testing"
)

const cyclonedx = `{
  "bomFormat": "CycloneDX", "specVersion": "1.5",
  "metadata": {"component": {"name": "my-app", "version": "1.0.0"}},
  "components": [
    {"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15",
     "components": [{"type": "library", "name": "nested", "version": "1.0.0", "purl": "pkg:npm/nested@1.0.0"}]},
    {"type": "library", "name": "no-purl", "version": "1.0"}
  ]
}`

const spdx = `{
  "spdxVersion": "SPDX-2.3", "name": "my-image",
  "packages": [
    {"name": "openssl", "versionInfo": "3.0.1",
     "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:deb/debian/openssl@3.0.1"}]},
    {"name": "readme", "versionInfo": ""}
  ]
}`

func TestParseCycloneDX(t *testing.T) {
	doc, err := Parse(strings.NewReader(cyclonedx))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Format != "CycloneDX" || doc.Name != "my-app" || len(doc.Assets) != 2 || doc.Skipped != 1 {
		t.Fatalf("unexpected document: %+v", doc)
	}
	if doc.Assets[1].Name != "nested" || doc.Assets[0].Source != "sbom" {
		t.Fatalf("unexpected assets: %+v", doc.Assets)
	}
}

func TestParseWithByteOrderMark(t *testing.T) {
	if _, err := Parse(strings.NewReader("\xef\xbb\xbf" + cyclonedx)); err != nil {
		t.Fatal(err)
	}
}

func TestParseSPDX(t *testing.T) {
	doc, err := Parse(strings.NewReader(spdx))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Format != "SPDX" || len(doc.Assets) != 1 || doc.Assets[0].Version != "3.0.1" {
		t.Fatalf("unexpected document: %+v", doc)
	}
}

func TestParseRejectsUnknown(t *testing.T) {
	if _, err := Parse(strings.NewReader(`{"hello": "world"}`)); err == nil {
		t.Fatal("unknown format accepted")
	}
}

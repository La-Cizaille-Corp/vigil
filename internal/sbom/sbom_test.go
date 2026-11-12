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

// A component keeps its CPE when it is a CPE 2.3 name; another one is
// dropped, the component kept by its purl.
func TestComponentCPE(t *testing.T) {
	doc, err := Parse(strings.NewReader(`{"bomFormat": "CycloneDX", "components": [
	  {"type": "library", "name": "nginx", "version": "1.24.0", "purl": "pkg:generic/nginx@1.24.0",
	   "cpe": "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"},
	  {"type": "library", "name": "openssl", "version": "3.0.1", "purl": "pkg:generic/openssl@3.0.1",
	   "cpe": "cpe:2.3:a:openssl:openssl:3.0.1"},
	  {"type": "library", "name": "zlib", "version": "1.3", "purl": "pkg:generic/zlib@1.3", "cpe": "cpe:/a:zlib:zlib:1.3"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Assets) != 3 || doc.Skipped != 0 || doc.Assets[0].CPE != "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*" ||
		doc.Assets[1].CPE != "" || doc.Assets[2].CPE != "" {
		t.Errorf("components: %d kept, %d skipped: %+v", len(doc.Assets), doc.Skipped, doc.Assets)
	}
}

// A file past MaxSize is refused with a message that says so: it spoke of a
// network answer of 20971520 bytes, for a file sent by the user.
func TestParseTooLarge(t *testing.T) {
	big := strings.NewReader(cyclonedx + strings.Repeat(" ", MaxSize))
	if _, err := Parse(big); err == nil || err.Error() != "fichier supérieur à 20 Mo" {
		t.Errorf("SBOM past %d bytes: %v", MaxSize, err)
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

// An empty or unusable SBOM would remove every asset of the project, and
// their triage history with them: it is refused.
func TestParseRefusesEmpty(t *testing.T) {
	for _, doc := range []string{
		`{"bomFormat":"CycloneDX","components":[]}`,
		`{"bomFormat":"CycloneDX","components":[{"type":"library","name":""}]}`,
	} {
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Errorf("accepted: %s", doc)
		}
	}
}

// Trivy gives the source package of a binary one as a property: advisories only
// name the source package.
func TestTrivySourcePackage(t *testing.T) {
	doc, err := Parse(strings.NewReader(`{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
	  {"type": "library", "name": "libssl3", "version": "3.0.11-1", "purl": "pkg:deb/debian/libssl3@3.0.11-1?arch=amd64&distro=debian-12",
	   "properties": [{"name": "aquasecurity:trivy:SrcName", "value": "openssl"}]},
	  {"type": "library", "name": "curl", "version": "7.88.1", "purl": "pkg:deb/debian/curl@7.88.1",
	   "properties": [{"name": "aquasecurity:trivy:SrcName", "value": "curl"}]},
	  {"type": "library", "name": "libc6", "version": "2.36", "purl": "pkg:deb/debian/libc6@2.36?upstream=glibc",
	   "properties": [{"name": "aquasecurity:trivy:SrcName", "value": "other"}]},
	  {"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15",
	   "properties": [{"name": "aquasecurity:trivy:PkgType", "value": "npm"}]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"pkg:deb/debian/libssl3@3.0.11-1?arch=amd64&distro=debian-12&upstream=openssl",
		"pkg:deb/debian/curl@7.88.1?upstream=curl",
		"pkg:deb/debian/libc6@2.36?upstream=glibc",
		"pkg:npm/lodash@4.17.15",
	}
	for i, a := range doc.Assets {
		if a.PURL != want[i] {
			t.Errorf("purl = %q, want %q", a.PURL, want[i])
		}
	}
}

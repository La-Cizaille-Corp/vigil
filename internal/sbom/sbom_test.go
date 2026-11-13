package sbom

import (
	"runtime"
	"slices"
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

// A document of empty values made the decoder hold 2 to 3 GB, every element a
// structure, before the bound of components was checked: past the values a
// real SBOM of 20 MB holds, it is refused before it is decoded.
func TestParseTooManyValues(t *testing.T) {
	for _, item := range []string{"0", "{}", `""`} {
		doc := `{"bomFormat":"CycloneDX","components":[` + strings.Repeat(item+",", 19<<20/(len(item)+1)) + item + `]}`
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := Parse(strings.NewReader(doc))
		runtime.ReadMemStats(&after)
		allocated := (after.TotalAlloc - before.TotalAlloc) >> 20
		if err == nil || err.Error() != "document trop complexe : plus de 2000000 valeurs JSON" || allocated > 200 {
			t.Errorf("%d MB of %s: %d MB allocated, %v", len(doc)>>20, item, allocated, err)
		}
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

// A file that is not a valid SBOM says why in French, without the Go names of
// encoding/json (audit UX 7.3, A88).
func TestParseErrorsInFrench(t *testing.T) {
	for doc, want := range map[string]string{
		`{"bomFormat":"CycloneDX","components":"lodash"}`:      "ce n'est pas un SBOM CycloneDX valide : components doit être une liste, pas un texte",
		`{"bomFormat":"CycloneDX","components":[{"name":12}]}`: "ce n'est pas un SBOM CycloneDX valide : components.0.name doit être un texte, pas un nombre",
		`{"spdxVersion":"SPDX-2.3","packages":{}}`:             "ce n'est pas un SBOM SPDX valide : packages doit être une liste, pas un objet",
		`{"bomFormat": "CycloneDX",`:                           "ce n'est pas un SBOM au format JSON : le fichier est incomplet",
		`<?xml version="1.0"?><bom/>`:                          "ce n'est pas un SBOM au format JSON : JSON illisible à l'octet 1",
	} {
		_, err := Parse(strings.NewReader(doc))
		if err == nil || err.Error() != want {
			t.Errorf("%s:\n got %v\nwant %s", doc, err, want)
		}
	}
}

// A document of another format is refused. So is an empty or unusable SBOM:
// it would remove every asset of the project, and their triage history with
// them.
func TestParseRefuses(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown format":         `{"hello": "world"}`,
		"no component":           `{"bomFormat":"CycloneDX","components":[]}`,
		"component without name": `{"bomFormat":"CycloneDX","components":[{"type":"library","name":""}]}`,
	} {
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Errorf("%s accepted: %s", name, doc)
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
	var got []string
	for _, a := range doc.Assets {
		got = append(got, a.PURL)
	}
	if !slices.Equal(got, want) {
		t.Errorf("purls\n%q\nwant\n%q", got, want)
	}
}

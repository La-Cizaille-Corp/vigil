package tracking_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/sources/osv"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/storetest"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

func openIDs(t *testing.T, st *store.Store, assetID int64) []string {
	t.Helper()
	findings, err := st.ListFindings(context.Background(), store.Everything, store.FindingFilter{AssetID: assetID})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range findings {
		if f.Status != "resolved" {
			ids = append(ids, f.VulnID)
		}
	}
	slices.Sort(ids)
	return ids
}

// A package kept at its latest release is affected by the advisories that
// have no fixed version yet, and no longer once the fix is out.
func TestLatestPackage(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	openEvents, modified := `[{"introduced":"2.0.0"}]`, "2026-10-01T00:00:00Z"
	syncer, srv := osvSyncer(t, st, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Package osv.Package `json:"package"`
			Version string      `json:"version"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path != "/v1/query" || body.Package.PURL != "pkg:npm/left" || body.Version != "" {
			t.Errorf("unexpected query %s %+v", r.URL.Path, body)
		}
		io.WriteString(w, `{"vulns":[
			{"id":"GHSA-open","modified":"`+modified+`","published":"2026-10-01T00:00:00Z",
			 "affected":[{"package":{"purl":"pkg:npm/left"},"ranges":[{"type":"SEMVER","events":`+openEvents+`}]}]},
			{"id":"GHSA-fixed","modified":"2026-10-01T00:00:00Z","published":"2026-10-01T00:00:00Z",
			 "affected":[{"package":{"purl":"pkg:npm/left"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}]}]}`)
	}, false)

	id, err := st.CreateAsset(ctx, store.Everything, store.Asset{Name: "left", Kind: "package", PURL: "pkg:npm/left@1.0.0", Version: "latest",
		Criticality: "medium", Source: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := syncer.Run(ctx); err != nil || res.Created != 1 {
		t.Fatalf("first sync: %+v, %v", res, err)
	}
	if got := openIDs(t, st, id); !slices.Equal(got, []string{"GHSA-open"}) {
		t.Errorf("findings = %v", got)
	}
	if _, err := st.Vulnerability(ctx, "GHSA-fixed"); err == nil {
		t.Error("an advisory that does not concern the asset was stored")
	}

	// The fix is released: the finding is marked fixed.
	srv.locked(func() { openEvents, modified = `[{"introduced":"2.0.0"},{"fixed":"2.0.1"}]`, "2026-10-20T00:00:00Z" })
	if res, err := syncer.Run(ctx); err != nil || res.Resolved != 1 {
		t.Fatalf("after the fix: %+v, %v", res, err)
	}
	if got := openIDs(t, st, id); len(got) != 0 {
		t.Errorf("still open: %v", got)
	}
}

const (
	cveAwaiting = `{"cve":{"id":"CVE-2026-1001","vulnStatus":"Awaiting Analysis","published":"2026-10-01T00:00:00.000",
		"descriptions":[{"lang":"en","value":"A flaw in Ivanti Connect Secure."}]}}`
	cveFixedBefore = `{"cve":{"id":"CVE-2026-1002","vulnStatus":"Analyzed","published":"2026-10-01T00:00:00.000",
		"descriptions":[{"lang":"en","value":"Ivanti Connect Secure before 22.7 allows..."}],
		"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*","versionEndExcluding":"22.7"}]}]}]}}`
	cveInRange = `{"cve":{"id":"CVE-2026-1003","vulnStatus":"Analyzed","published":"2026-10-01T00:00:00.000",
		"descriptions":[{"lang":"en","value":"Ivanti Connect Secure 22.7 before 22.8 allows..."}],
		"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*","versionStartIncluding":"22.7","versionEndExcluding":"22.8"}]}]}]}}`
	cveOpen = `{"cve":{"id":"CVE-2026-1004","vulnStatus":"Analyzed","published":"2026-10-01T00:00:00.000",
		"descriptions":[{"lang":"en","value":"Every Ivanti Connect Secure version allows..."}],
		"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*"}]}]}]}}`
)

// An asset with neither purl nor CPE is searched by its name in the NVD; the
// configurations, when there are some, check its version. A CPE asset at its
// latest release keeps the CVEs without a fixed version.
func TestByNameAndLatestCPE(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	var keywords []string
	syncer, _ := nvdSyncer(t, st, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		list := cveAwaiting + "," + cveFixedBefore + "," + cveInRange + "," + cveOpen
		switch {
		case q.Has("keywordSearch"):
			keywords = append(keywords, q.Get("keywordSearch"))
		case q.Get("virtualMatchString") == "cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*":
			list = cveFixedBefore + "," + cveInRange + "," + cveOpen
		default:
			t.Errorf("unexpected query %s", r.URL.RawQuery)
		}
		io.WriteString(w, `{"totalResults":4,"vulnerabilities":[`+list+`]}`)
	})

	add := func(a store.Asset) int64 {
		a.Kind, a.Criticality = "product", "high"
		if a.Source == "" {
			a.Source = "manual"
		}
		id, err := st.CreateAsset(ctx, store.Everything, a)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	versioned := add(store.Asset{Name: "Ivanti Connect Secure", Version: "22.7.1"})
	latest := add(store.Asset{Name: "Ivanti Connect Secure", Version: "latest"})
	cpeLatest := add(store.Asset{Name: "ICS", Version: "latest", CPE: "cpe:2.3:a:ivanti:connect_secure:22.7:*:*:*:*:*:*:*"})
	add(store.Asset{Name: "libc.so.6", Version: "2.36", Source: "sbom", Project: "app"})

	if _, err := syncer.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := openIDs(t, st, versioned); !slices.Equal(got, []string{"CVE-2026-1001", "CVE-2026-1003", "CVE-2026-1004"}) {
		t.Errorf("by name, version 22.7.1: %v", got)
	}
	if got := openIDs(t, st, latest); !slices.Equal(got, []string{"CVE-2026-1001", "CVE-2026-1004"}) {
		t.Errorf("by name, latest: %v", got)
	}
	if got := openIDs(t, st, cpeLatest); !slices.Equal(got, []string{"CVE-2026-1004"}) {
		t.Errorf("CPE, latest: %v", got)
	}
	// The product of the CPE is searched too, for the CVEs awaiting analysis
	// that its CNA declares (A101): CVE-2026-1001 declares nothing.
	if !slices.Equal(keywords, []string{"connect secure", "Ivanti Connect Secure", "Ivanti Connect Secure"}) {
		t.Errorf("names searched: %v (an SBOM component must not be)", keywords)
	}
}

// Records awaiting analysis, as the NVD relays them with what their CNA
// declares (shapes of November 2026).
const (
	cveGitLabDeclared = `{"cve":{"id":"CVE-2026-16545","vulnStatus":"Awaiting Analysis","published":"2026-11-17T00:00:00.000",
		"descriptions":[{"lang":"en","value":"An issue has been discovered in GitLab CE/EE."}],
		"affected":[{"source":"cve@gitlab.com","affectedData":[{"vendor":"GitLab","product":"GitLab","defaultStatus":"unaffected","versions":[
			{"version":"19.4","lessThan":"19.4.8","versionType":"semver","status":"affected"},
			{"version":"19.5","lessThan":"19.5.6","versionType":"semver","status":"affected"}]}]}]}}`
	cveXWEB = `{"cve":{"id":"CVE-2026-124002","vulnStatus":"Deferred","published":"2026-11-12T00:00:00.000",
		"descriptions":[{"lang":"en","value":"XWEB EVO allows command injection. This product line reached it's end of service date in March 2026."}],
		"affected":[{"source":"disclosure@vulncheck.com","affectedData":[{"vendor":"Copeland","product":"XWEB EVO","defaultStatus":"unaffected","versions":[
			{"version":"5.2.3","lessThan":"5.7.0","versionType":"semver","status":"affected"}]}]}]}}`
)

// Before the NVD analyses a CVE, it counts for the product its CNA declares
// (A101): a CPE asset gets it, with the version that fixes it, and an asset
// whose name is merely a word of its description does not.
func TestDeclaredByTheCNA(t *testing.T) {
	ctx := context.Background()
	st := storetest.Open(t)
	syncer, _ := nvdSyncer(t, st, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		list := ""
		switch {
		case q.Get("keywordSearch") == "gitlab":
			list = cveGitLabDeclared
		case q.Get("keywordSearch") == "date":
			list = cveXWEB
		case q.Has("cpeName"): // the NVD has analysed nothing yet
		default:
			t.Errorf("unexpected query %s", r.URL.RawQuery)
		}
		io.WriteString(w, `{"totalResults":1,"vulnerabilities":[`+list+`]}`)
	})
	add := func(a store.Asset) store.Asset {
		a.Kind, a.Criticality, a.Source = "product", "high", "manual"
		id, err := st.CreateAsset(ctx, store.Everything, a)
		if err != nil {
			t.Fatal(err)
		}
		a.ID = id
		return a
	}
	gitlab := add(store.Asset{Name: "GitLab", Version: "19.5.3", CPE: "cpe:2.3:a:gitlab:gitlab:19.5.3:*:*:*:enterprise:*:*:*"})
	date := add(store.Asset{Name: "date", Version: "3.0.4"})

	if _, err := syncer.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := openIDs(t, st, gitlab.ID); !slices.Equal(got, []string{"CVE-2026-16545"}) {
		t.Errorf("CPE: %v", got)
	}
	if got := openIDs(t, st, date.ID); len(got) != 0 {
		t.Errorf("by name: %v", got)
	}
	v, err := st.Vulnerability(ctx, "CVE-2026-16545")
	if err != nil {
		t.Fatal(err)
	}
	fixes := tracking.Fixes(v.Raw, gitlab)
	if !slices.ContainsFunc(fixes, func(f tracking.Fix) bool { return f.Fixed == "19.5.6" && f.Yours }) {
		t.Errorf("fixes: %+v", fixes)
	}
}

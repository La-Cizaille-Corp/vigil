// Package osv is a minimal client for the OSV.dev API (https://osv.dev).
package osv

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/cvss"
	"github.com/La-Cizaille-Corp/vigil/internal/limit"
	"github.com/La-Cizaille-Corp/vigil/internal/sources"
	"github.com/La-Cizaille-Corp/vigil/internal/versions"
)

// DefaultURL is the public OSV API.
const DefaultURL = "https://api.osv.dev"

// Timeout is the time limit an OSV request needs, longer than that of the
// other sources: a page of /v1/query can take minutes to read.
const Timeout = 5 * time.Minute

// maxBatch is the OSV limit of queries per querybatch call.
const maxBatch = 1000

// maxBody bounds every response read at once, and every advisory, read alone
// or in a page; maxPage a page of /v1/query, read advisory by advisory:
// thousands of them, each listing many packages. A page weighs 72 MB on
// average and the heaviest advisory 708 KB (ARCHITECTURE.md, A55, A62 and
// A75); the heaviest page is not measured, hence the margin. One advisory at a
// time is held in memory.
const (
	maxBody = 32 << 20
	maxPage = 1 << 30
)

// Client talks to OSV. Its HTTP client is that of the other sources, with the
// same transport and redirect policy, but a time limit of Timeout.
type Client struct {
	URL       string // empty: DefaultURL
	HTTP      *http.Client
	UserAgent string
}

// Package identifies a package, either by purl or by name and ecosystem.
type Package struct {
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

// Query asks which vulnerabilities affect a package version.
type Query struct {
	Package Package `json:"package"`
	Version string  `json:"version,omitempty"`
}

// page returns the body that asks OSV for a page of the answer to q: the
// first one, or the one of a token of the page before.
func (q Query) page(token string) map[string]any {
	body := map[string]any{"package": q.Package}
	if q.Version != "" {
		body["version"] = q.Version
	}
	if token != "" {
		body["page_token"] = token
	}
	return body
}

// VulnRef is the short form returned by querybatch.
type VulnRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// SameModified reports whether two modification dates of an advisory are the
// same: querybatch writes them to the microsecond, a full record to the
// nanosecond (2026-11-12T17:20:40.464641Z, 2026-11-12T17:20:40.464641664Z).
// Dates that cannot be read are compared as written.
func SameModified(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339Nano, a)
	tb, errB := time.Parse(time.RFC3339Nano, b)
	if errA != nil || errB != nil {
		return a == b
	}
	return ta.Truncate(time.Microsecond).Equal(tb.Truncate(time.Microsecond))
}

// Vuln is the subset of the OSV schema we use.
type Vuln struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected  []Affected `json:"affected"`
	Withdrawn string     `json:"withdrawn"`
	// Upstream names the advisories this one derives from: the CVE of a
	// DEBIAN-CVE-… record, which has no alias.
	Upstream []string `json:"upstream"`
}

// Compact returns the advisory as it is kept: the ranges of its packages, which
// tell the versions fixing it. Everything else is in the columns of the database,
// or never read: a UBUNTU-CVE-… weighs 600 KB, for 257 packages with their
// binaries and versions, so 2 GB for the 3 000 advisories of a kernel.
func (v Vuln) Compact() []byte {
	type entry struct {
		Package Package `json:"package"`
		Ranges  []Range `json:"ranges,omitempty"`
	}
	doc := struct {
		ID       string  `json:"id"`
		Affected []entry `json:"affected,omitempty"`
	}{ID: v.ID}
	for _, a := range v.Affected {
		e := entry{Package: a.Package}
		for _, r := range a.Ranges {
			if r.Type != "GIT" { // commits, never compared
				e.Ranges = append(e.Ranges, r)
			}
		}
		if len(e.Ranges) > 0 {
			doc.Affected = append(doc.Affected, e)
		}
	}
	out, err := json.Marshal(doc)
	if err != nil { // strings and lists only: cannot happen
		return nil
	}
	return out
}

// OtherIDs returns the identifiers of the same vulnerability elsewhere: its
// aliases and upstream advisories.
func (v Vuln) OtherIDs() []string {
	out := slices.Clone(v.Aliases)
	for _, id := range v.Upstream {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// Affected is a package named by an advisory, with its affected ranges.
type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []Range  `json:"ranges"`
	Versions []string `json:"versions"`
}

// Range lists the events of an affected range, in the advisory's order:
// {"introduced": "0"}, {"fixed": "4.17.21"}, {"last_affected": "1.2.3"}…
type Range struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

// Intervals returns the affected intervals of a range of versions; none for
// a range of commits.
func (r Range) Intervals() []versions.Range {
	if r.Type == "GIT" {
		return nil
	}
	var out []versions.Range
	var iv versions.Range
	open := false
	for _, e := range r.Events {
		switch {
		case e["introduced"] != "":
			iv, open = versions.Range{Start: e["introduced"]}, true
		case e["fixed"] != "":
			iv.Fixed = e["fixed"]
			out = append(out, iv)
			iv, open = versions.Range{}, false
		case e["last_affected"] != "":
			iv.LastAffected = e["last_affected"]
			out = append(out, iv)
			iv, open = versions.Range{}, false
		}
	}
	if open {
		out = append(out, iv)
	}
	return out
}

// For returns the entries of the advisory that concern pkg: same purl
// (version and qualifiers aside), or same name in the same ecosystem
// (Debian matches Debian:12). An entry without purl is taken for a purl
// query when it is the only one.
func (v Vuln) For(pkg Package) []Affected {
	var out []Affected
	for _, a := range v.Affected {
		switch {
		case pkg.PURL != "" && a.Package.PURL != "":
			if purlBase(a.Package.PURL) != purlBase(pkg.PURL) {
				continue
			}
		case pkg.PURL != "":
			if len(v.Affected) > 1 {
				continue
			}
		case !strings.EqualFold(a.Package.Name, pkg.Name) ||
			a.Package.Ecosystem != pkg.Ecosystem && !strings.HasPrefix(a.Package.Ecosystem, pkg.Ecosystem+":"):
			continue
		}
		out = append(out, a)
	}
	return out
}

// Unfixed reports whether the advisory still affects the latest release of
// pkg: one of its ranges ends affected, after "introduced" (no fixed version
// yet) or "last_affected" (affected up to that version, no fix indicated).
// A withdrawn advisory affects nothing.
func (v Vuln) Unfixed(pkg Package) bool {
	if v.Withdrawn != "" {
		return false
	}
	for _, a := range v.For(pkg) {
		for _, r := range a.Ranges {
			open := false
			for _, e := range r.Events {
				switch {
				case e["introduced"] != "", e["last_affected"] != "":
					open = true
				case e["fixed"] != "":
					open = false
				}
			}
			if open {
				return true
			}
		}
	}
	return false
}

// Affects reports whether the advisory affects a version of pkg, by its own
// ranges: OSV does not compare versions for every ecosystem (Linux).
func (v Vuln) Affects(pkg Package, version string) bool {
	if v.Withdrawn != "" {
		return false
	}
	for _, a := range v.For(pkg) {
		if slices.Contains(a.Versions, version) {
			return true
		}
		for _, r := range a.Ranges {
			for _, iv := range r.Intervals() {
				if iv.Holds(version) {
					return true
				}
			}
		}
	}
	return false
}

// purlBase drops the version, qualifiers and subpath of a purl, lower case:
// pkg:npm/lodash@4.17.15?x=y → pkg:npm/lodash.
func purlBase(purl string) string {
	base, _, _ := strings.Cut(purl, "#")
	base, _, _ = strings.Cut(base, "?")
	base, _, _ = strings.Cut(base, "@")
	return strings.ToLower(base)
}

// versionSpan locates the version of a purl: from its @ at the end of the path,
// up to the qualifiers. at is -1 without version: an @ further on is in a
// qualifier (upstream=glibc@2.36), one that starts a segment is a scope
// (pkg:npm/@babel/core).
func versionSpan(purl string) (at, end int) {
	end = len(purl)
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		end = i
	}
	at = strings.LastIndex(purl[:end], "@")
	if at > 0 && purl[at-1] == '/' {
		at = -1
	}
	return at, end
}

// WithoutVersion drops the version of a purl, keeping its qualifiers:
// pkg:npm/lodash@4.17.15 → pkg:npm/lodash.
func WithoutVersion(purl string) string {
	at, end := versionSpan(purl)
	if at < 0 {
		return purl
	}
	return purl[:at] + purl[end:]
}

// PURLName returns the name of the package a purl designates, decoded, ""
// when it names none (pkg:npm, pkg:npm/@4.17.21, pkg:npm/@babel/):
// pkg:npm/%40babel/core@7.0.0 → core.
func PURLName(purl string) string {
	at, end := versionSpan(purl)
	if at < 0 {
		at = end
	}
	kind, path, ok := strings.Cut(strings.TrimPrefix(purl[:at], "pkg:"), "/")
	if !ok || kind == "" {
		return ""
	}
	name := path[strings.LastIndex(path, "/")+1:]
	if strings.HasPrefix(name, "@") { // a scope without its package
		return ""
	}
	return purlDecode(name)
}

// PURLVersion returns the version written in a purl, decoded:
// pkg:deb/debian/libssl3@1%3A3.0.11?distro=debian-12 → 1:3.0.11.
func PURLVersion(purl string) string {
	at, end := versionSpan(purl)
	if at < 0 {
		return ""
	}
	return purlDecode(purl[at+1 : end])
}

// PURLQuery returns what to ask OSV for a purl at a version. A version that
// differs from the one written in the purl overrides it: it is the Version
// field of an asset, which people update and which the pages show. Without one,
// or with the same one, the purl decides, and the source package it names keeps
// its own version. A release named by the distro qualifier becomes an
// ecosystem: OSV finds nothing for pkg:deb/debian/x?distro=debian-12, and
// without the release it compares the version with the advisories of all of
// them, where any version of Debian 12 is below the fix of Debian 14.
func PURLQuery(purl, version string) Query {
	source := sourcePURL(purl)
	if version != "" && purlDecode(version) != PURLVersion(purl) {
		source = WithoutVersion(source)
	}
	withoutSubpath, _, _ := strings.Cut(purl, "#")
	_, rawQualifiers, _ := strings.Cut(withoutSubpath, "?")
	qualifiers, _ := url.ParseQuery(rawQualifiers) // on error, what could be read
	if parts := strings.Split(strings.TrimPrefix(source, "pkg:"), "/"); len(parts) == 3 {
		if ecosystem := releaseEcosystem(parts[1], qualifiers.Get("distro")); ecosystem != "" {
			name, purlVersion, versioned := strings.Cut(parts[2], "@")
			if versioned {
				version = purlDecode(purlVersion)
			}
			return Query{Package: Package{Name: purlDecode(name), Ecosystem: ecosystem}, Version: version}
		}
	}
	if PURLVersion(source) != "" {
		version = "" // a purl that carries a version must not be sent with one
	}
	return Query{Package: Package{PURL: source}, Version: version}
}

func purlDecode(s string) string {
	if decoded, err := url.PathUnescape(s); err == nil {
		return decoded
	}
	return s
}

var (
	debianReleases = map[string]string{"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}
	ubuntuReleases = map[string]string{"focal": "20.04", "jammy": "22.04", "noble": "24.04"}
)

// releaseEcosystem returns the OSV ecosystem of a release of a distribution,
// from the namespace of a purl and its distro qualifier: debian-12.5 or
// bookworm, ubuntu-22.04, alpine-3.18.4, rocky-9.3. It is "" when unknown.
func releaseEcosystem(namespace, distro string) string {
	release := strings.ToLower(distro)
	if i := strings.LastIndex(release, "-"); i >= 0 {
		release = release[i+1:]
	}
	if known, ok := debianReleases[release]; ok && namespace == "debian" {
		release = known
	}
	if known, ok := ubuntuReleases[release]; ok && namespace == "ubuntu" {
		release = known
	}
	major, rest, _ := strings.Cut(release, ".")
	minor, _, _ := strings.Cut(rest, ".")
	if _, err := strconv.Atoi(major); err != nil {
		return ""
	}
	switch namespace {
	case "debian":
		return "Debian:" + major
	case "rocky":
		return "Rocky Linux:" + major
	case "almalinux":
		return "AlmaLinux:" + major
	case "alpine":
		if minor != "" {
			return "Alpine:v" + major + "." + minor
		}
	case "ubuntu":
		if minor != "" {
			year, _ := strconv.Atoi(major)
			if minor == "04" && year%2 == 0 {
				return "Ubuntu:" + major + ".04:LTS"
			}
			return "Ubuntu:" + major + "." + minor
		}
	}
	return ""
}

// sourcePURL returns a purl without what OSV cannot match: its qualifiers, and
// the name of a binary package. OSV files the packages of a distribution under
// their source package: the upstream qualifier of an SBOM (linux-image-amd64,
// upstream=linux) gives it, as kernelSource does for the names of a kernel.
func sourcePURL(purl string) string {
	purl, _, _ = strings.Cut(purl, "#")
	base, rawQualifiers, _ := strings.Cut(purl, "?")
	slash := strings.LastIndex(base, "/")
	kind, _, _ := strings.Cut(strings.TrimPrefix(base, "pkg:"), "/")
	if slash < 0 || kind != "deb" && kind != "rpm" && kind != "apk" {
		return base
	}
	name, version, versioned := strings.Cut(base[slash+1:], "@")
	qualifiers, _ := url.ParseQuery(rawQualifiers) // on error, what could be read
	if source, sourceVersion := upstreamPackage(kind, qualifiers.Get("upstream")); source != "" {
		name = source
		if sourceVersion != "" {
			version, versioned = sourceVersion, true
		}
	}
	name = kernelSource(name, kind)
	if !versioned {
		return base[:slash+1] + name
	}
	return base[:slash+1] + name + "@" + version
}

// upstreamPackage reads the upstream qualifier of a purl: name or
// name@version, or the source RPM for Red Hat
// (kernel-5.14.0-362.el9.src.rpm, whose version is the package's).
func upstreamPackage(kind, upstream string) (name, version string) {
	if kind != "rpm" {
		name, version, _ = strings.Cut(upstream, "@")
		return name, version
	}
	parts := strings.Split(strings.TrimSuffix(upstream, ".src.rpm"), "-")
	if len(parts) < 3 {
		return "", ""
	}
	return strings.Join(parts[:len(parts)-2], "-"), ""
}

// ComparesVersions reports whether OSV finds the advisories of a version in an
// ecosystem. In Linux it has the ranges of kernel.org but does not compare them:
// the advisories of the package must be read and compared here.
func ComparesVersions(ecosystem string) bool { return ecosystem != "Linux" }

// SourceName returns the name of a package in the advisories of an ecosystem.
func SourceName(name, ecosystem string) string {
	distribution, _, _ := strings.Cut(ecosystem, ":") // Debian:12
	switch distribution {
	case "Linux":
		return "Kernel" // its only package
	case "Debian", "Ubuntu":
		return kernelSource(name, "deb")
	case "Red Hat", "Rocky Linux", "AlmaLinux":
		return kernelSource(name, "rpm")
	}
	return name
}

// kernelPackages are the binary packages of a kernel, by prefix, with their
// source package: SBOMs list the former, advisories name the latter.
var kernelPackages = []struct{ kind, prefix, source string }{
	{"deb", "linux-image-", "linux"}, {"deb", "linux-headers-", "linux"}, {"deb", "linux-modules-", "linux"},
	{"deb", "linux-tools-", "linux"}, {"deb", "linux-libc-dev", "linux"}, {"deb", "linux-signed", "linux"},
	{"rpm", "kernel-", "kernel"},
}

func kernelSource(name, kind string) string {
	for _, p := range kernelPackages {
		if p.kind == kind && strings.HasPrefix(strings.ToLower(name), p.prefix) {
			return p.source
		}
	}
	return name
}

// CVSSScore returns the highest CVSS 3.x base score computed from the
// advisory vectors, or cvss.Unknown.
func (v Vuln) CVSSScore() float64 {
	best := cvss.Unknown
	for _, s := range v.Severity {
		best = max(best, cvss.BaseScore(s.Score))
	}
	return best
}

// databaseSeverities translates the severity scales of the databases into
// the ratings of CVSS: GitHub's MODERATE, Red Hat's Important, the priorities
// of Ubuntu (negligible to critical).
var databaseSeverities = map[string]string{
	"CRITICAL": "CRITICAL", "HIGH": "HIGH", "IMPORTANT": "HIGH",
	"MEDIUM": "MEDIUM", "MODERATE": "MEDIUM", "LOW": "LOW", "NEGLIGIBLE": "LOW",
}

// distributionPriority is the severity type of OSV under which a distribution
// gives its own priority: Ubuntu rates every CVE it tracks, including those
// the NVD has not analysed yet.
const distributionPriority = "Ubuntu"

// SeverityLabel returns the advisory severity (e.g. HIGH) when the database
// provides one on a known scale, otherwise the rating of the CVSS score,
// otherwise the priority of the distribution, otherwise "". The priority
// comes after the score: Ubuntu rates lower than the score for most of the
// kernel CVEs both rate, and it would class them less urgent than the others.
func (v Vuln) SeverityLabel() string {
	if s, ok := databaseSeverities[strings.ToUpper(v.DatabaseSpecific.Severity)]; ok {
		return s
	}
	if s := cvss.Severity(v.CVSSScore()); s != "" {
		return s
	}
	for _, s := range v.Severity {
		if s.Type == distributionPriority {
			return databaseSeverities[strings.ToUpper(s.Score)]
		}
	}
	return ""
}

// BatchResult answers one query of a batch: the first page of its
// vulnerabilities. With More, there are others, and OSV lists from the oldest:
// read them all with Refs, or in full with Advisories.
type BatchResult struct {
	Vulns []VulnRef
	More  bool
}

// batchAnswer is the answer of querybatch: a page of each query.
type batchAnswer struct {
	Results []struct {
		Vulns         []VulnRef `json:"vulns"`
		NextPageToken string    `json:"next_page_token"`
	} `json:"results"`
}

// batch sends queries, at most maxBatch, to querybatch.
func (c *Client) batch(ctx context.Context, queries []any) (batchAnswer, error) {
	var resp batchAnswer
	if err := c.do(ctx, http.MethodPost, "/v1/querybatch", map[string]any{"queries": queries}, &resp); err != nil {
		return resp, err
	}
	if len(resp.Results) != len(queries) {
		return resp, fmt.Errorf("osv querybatch: got %d results for %d queries", len(resp.Results), len(queries))
	}
	return resp, nil
}

// QueryBatch returns, for each query, the vulnerabilities affecting it.
func (c *Client) QueryBatch(ctx context.Context, queries []Query) ([]BatchResult, error) {
	out := make([]BatchResult, 0, len(queries))
	for start := 0; start < len(queries); start += maxBatch {
		end := min(start+maxBatch, len(queries))
		page := make([]any, 0, end-start)
		for _, q := range queries[start:end] {
			page = append(page, q.page(""))
		}
		resp, err := c.batch(ctx, page)
		if err != nil {
			return nil, err
		}
		for _, r := range resp.Results {
			out = append(out, BatchResult{Vulns: r.Vulns, More: r.NextPageToken != ""})
		}
	}
	return out, nil
}

// maxQueryPages bounds the pages read for one query: OSV answers a heavy one
// in many pages, sometimes empty (more than twenty for the Ubuntu kernel).
const maxQueryPages = 200

// Refs lists every advisory matching a query in short, its id and date of
// modification: the pages of the batch answer, a thousand advisories each. It
// is light where Advisories is heavy: 600 KB for the 8 215 advisories of an
// Ubuntu kernel, against 4.5 GB (ARCHITECTURE.md, A90).
func (c *Client) Refs(ctx context.Context, q Query) ([]VulnRef, error) {
	var out []VulnRef
	token := ""
	for range maxQueryPages {
		resp, err := c.batch(ctx, []any{q.page(token)})
		if err != nil {
			return nil, err
		}
		out = append(out, resp.Results[0].Vulns...)
		if token = resp.Results[0].NextPageToken; token == "" {
			return out, nil
		}
	}
	return nil, fmt.Errorf("osv querybatch: more than %d pages of results", maxQueryPages)
}

// Advisories reads every advisory matching a query, in full, one at a time and
// without keeping them: the Linux kernel has 150 MB of them. It takes no
// callback, so that this package never calls the code of its users.
//
//	list := client.Advisories(q)
//	defer list.Close()
//	for list.Next(ctx) {
//		use(list.Vuln())
//	}
//	err := list.Err()
type Advisories struct {
	client    *Client
	query     Query
	pageToken string // of the page being read, "" for the first one
	token     string // of the next page
	pages     int
	done      bool
	body      io.Closer      // of the page being read
	part      *limit.Limited // the page, bounded advisory by advisory
	dec       *json.Decoder
	inVulns   bool
	vuln      Vuln
	err       error
	// A page cut by the network is read again from its start: returned holds
	// the advisories of the page already returned, rereads how many times it
	// was asked for again. returned is nil before a new page.
	returned map[string]bool
	rereads  int
}

// Advisories returns the advisories matching q: those of a version, or of the
// whole package without one.
func (c *Client) Advisories(q Query) *Advisories { return &Advisories{client: c, query: q} }

// Vuln returns the advisory Next moved to.
func (a *Advisories) Vuln() Vuln { return a.vuln }

// Err returns the failure that ended the reading, if any.
func (a *Advisories) Err() error { return a.err }

// Close releases the page being read, for a reading stopped before the end.
func (a *Advisories) Close() {
	if a.body != nil {
		_ = a.body.Close() // only read from: nothing to lose
		a.body, a.part, a.dec = nil, nil, nil
	}
}

// Next moves to the next advisory; false at the end or after a failure.
func (a *Advisories) Next(ctx context.Context) bool {
	for a.err == nil && !a.done {
		var err error // reading the page; a failure to ask for it is final
		switch {
		case a.dec == nil:
			if a.err = a.openPage(ctx); a.err == nil {
				err = a.expect('{')
			}
		case a.inVulns && a.dec.More():
			if err = a.decodeVuln(); err == nil && !(a.rereads > 0 && a.returned[a.vuln.ID]) {
				a.returned[a.vuln.ID] = true
				return true
			}
		case a.inVulns:
			a.inVulns = false
			err = a.expect(']')
		case a.dec.More():
			err = a.readField()
		default: // end of the page
			if err = a.expect('}'); err == nil {
				a.Close()
				a.pageToken, a.returned, a.rereads = a.token, nil, 0
				a.done = a.token == ""
			}
		}
		if err != nil {
			a.err = a.readFailed(ctx, err)
		}
	}
	a.Close()
	return false
}

// readFailed handles a failure while reading a page. One cut by the network
// (sources.Temporary) is asked for again and read from its start, without
// returning twice an advisory: as many times as Client.send sends a request
// again, after the same delays. It returns nil then, otherwise the error that
// ends the reading.
func (a *Advisories) readFailed(ctx context.Context, err error) error {
	a.Close()
	a.inVulns = false
	if !sources.Temporary(err) {
		return fmt.Errorf("osv /v1/query: réponse illisible : %w", err)
	}
	delays := a.client.delays()
	if a.rereads == len(delays) || sources.Sleep(ctx, delays[a.rereads]) != nil {
		return fmt.Errorf("osv /v1/query: lecture interrompue : %w", err)
	}
	a.rereads++
	return nil
}

// openPage asks for the page of pageToken: the next one, or the same again
// after a cut.
func (a *Advisories) openPage(ctx context.Context) error {
	if a.returned == nil { // a new page
		if a.pages == maxQueryPages {
			return fmt.Errorf("osv query: more than %d pages of results", maxQueryPages)
		}
		a.pages++
		a.returned = map[string]bool{}
	}
	a.token = ""
	var page io.ReadCloser
	err := a.client.send(ctx, http.MethodPost, "/v1/query", a.query.page(a.pageToken), func(req *http.Request) (err error) {
		page, err = sources.Open(a.client.HTTP, req, maxPage)
		return err
	})
	if err != nil {
		return err
	}
	a.body = page
	a.part = limit.Reader(page, maxBody)
	a.dec = json.NewDecoder(a.part)
	return nil
}

// decodeVuln reads the next advisory of the page, within maxBody bytes as one
// read alone: a page of 1 GB could otherwise hold one advisory of 1 GB. The
// bytes counted are those read for it, the decoder reading ahead: it holds at
// most twice maxBody.
func (a *Advisories) decodeVuln() error {
	a.part.Renew()
	var v Vuln
	if err := a.dec.Decode(&v); err != nil {
		return err
	}
	a.vuln = v
	return nil
}

// readField reads a field of the page, up to the first advisory of its list.
func (a *Advisories) readField() error {
	a.part.Renew()
	key, err := a.dec.Token()
	if err != nil {
		return err
	}
	switch key {
	case "vulns":
		a.inVulns = true
		return a.expect('[')
	case "next_page_token":
		err = a.dec.Decode(&a.token)
	default:
		var skipped json.RawMessage
		err = a.dec.Decode(&skipped)
	}
	return err
}

// expect reads a delimiter of the page, which must be the one given.
// SECURITY: what came instead is named by its kind, never quoted: the error
// is shown and logged, and a text of the page could hold anything, up to the
// bound of the page.
func (a *Advisories) expect(delim json.Delim) error {
	token, err := a.dec.Token()
	if err != nil {
		return err
	}
	if token != delim {
		return fmt.Errorf("%s au lieu de %v", tokenKind(token), delim)
	}
	return nil
}

// tokenKind names a token of a page: a delimiter as it is, any other value by
// its kind (limit.JSONKind).
func tokenKind(token json.Token) string {
	switch token := token.(type) {
	case json.Delim:
		return string(token)
	case string:
		return limit.JSONKind("string")
	case bool:
		return limit.JSONKind("bool")
	case nil:
		return limit.JSONKind("null")
	}
	return limit.JSONKind("number")
}

// Vuln fetches the full record of a vulnerability.
func (c *Client) Vuln(ctx context.Context, id string) (Vuln, error) {
	var v Vuln
	if err := c.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &v); err != nil {
		return Vuln{}, err
	}
	return v, nil
}

// do sends a request and decodes its answer into out, read whole.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	return c.send(ctx, method, path, body, func(req *http.Request) error {
		return sources.Do(c.HTTP, req, maxBody, out)
	})
}

// retryDelays are the waits before asking again after a temporary failure: a
// network glitch on the batch request would fail the whole synchronisation.
var retryDelays = []time.Duration{5 * time.Second, 15 * time.Second}

// delays returns the waits before asking again: retryDelays for OSV, none for
// a test server or a mirror.
func (c *Client) delays() []time.Duration {
	if cmp.Or(c.URL, DefaultURL) != DefaultURL {
		return make([]time.Duration, len(retryDelays))
	}
	return retryDelays
}

// send makes a request to path and has it sent by call (sources.Do or Open),
// again after a temporary failure.
func (c *Client) send(ctx context.Context, method, path string, body any, call func(*http.Request) error) error {
	base := cmp.Or(c.URL, DefaultURL)
	err := sources.Retry(ctx, c.delays(), func() (bool, error) {
		req, err := sources.NewRequest(ctx, method, base+path, c.UserAgent, body)
		if err != nil {
			return false, err
		}
		err = call(req)
		return sources.Temporary(err), err
	})
	if err != nil {
		return fmt.Errorf("osv %s: %w", path, err)
	}
	return nil
}

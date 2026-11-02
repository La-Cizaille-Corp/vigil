// Package osv is a minimal client for the OSV.dev API (https://osv.dev).
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/cvss"
)

// DefaultBaseURL is the public OSV API.
const DefaultBaseURL = "https://api.osv.dev"

// maxBatch is the OSV limit of queries per querybatch call.
const maxBatch = 1000

// maxBody bounds every response we read.
const maxBody = 32 << 20

// Client talks to OSV.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string
}

// New returns a client with safe defaults.
func New(userAgent string) *Client {
	return &Client{
		BaseURL:   DefaultBaseURL,
		HTTP:      &http.Client{Timeout: 60 * time.Second},
		UserAgent: userAgent,
	}
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

// VulnRef is the short form returned by querybatch.
type VulnRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
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

	Raw json.RawMessage `json:"-"`
}

// Affected is a package named by an advisory, with its affected ranges.
type Affected struct {
	Package Package `json:"package"`
	Ranges  []Range `json:"ranges"`
}

// Range lists the events of an affected range, in the advisory's order:
// {"introduced": "0"}, {"fixed": "4.17.21"}, {"last_affected": "1.2.3"}…
type Range struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
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

// purlBase drops the version, qualifiers and subpath of a purl, lower case:
// pkg:npm/lodash@4.17.15?x=y → pkg:npm/lodash.
func purlBase(purl string) string {
	base, _, _ := strings.Cut(purl, "#")
	base, _, _ = strings.Cut(base, "?")
	base, _, _ = strings.Cut(base, "@")
	return strings.ToLower(base)
}

// WithoutVersion drops the version of a purl, keeping its qualifiers:
// pkg:npm/lodash@4.17.15 → pkg:npm/lodash.
func WithoutVersion(purl string) string {
	at := strings.LastIndex(purl, "@")
	if at < 0 {
		return purl
	}
	end := strings.IndexAny(purl[at:], "?#")
	if end < 0 {
		return purl[:at]
	}
	return purl[:at] + purl[at+end:]
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

// SeverityLabel returns the advisory severity (e.g. HIGH) when the database
// provides one, otherwise the rating of the CVSS score, otherwise "".
func (v Vuln) SeverityLabel() string {
	if s := strings.ToUpper(v.DatabaseSpecific.Severity); s != "" {
		if s == "MODERATE" {
			return "MEDIUM"
		}
		return s
	}
	return cvss.Severity(v.CVSSScore())
}

// QueryBatch returns, for each query, the vulnerabilities affecting it.
func (c *Client) QueryBatch(ctx context.Context, queries []Query) ([][]VulnRef, error) {
	out := make([][]VulnRef, 0, len(queries))
	for start := 0; start < len(queries); start += maxBatch {
		end := min(start+maxBatch, len(queries))
		var resp struct {
			Results []struct {
				Vulns []VulnRef `json:"vulns"`
			} `json:"results"`
		}
		body := map[string]any{"queries": queries[start:end]}
		if err := c.do(ctx, http.MethodPost, "/v1/querybatch", body, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != end-start {
			return nil, fmt.Errorf("osv querybatch: got %d results for %d queries", len(resp.Results), end-start)
		}
		for _, r := range resp.Results {
			out = append(out, r.Vulns)
		}
	}
	return out, nil
}

// maxQueryPages bounds the pages read for one package: OSV returns up to a
// thousand advisories per page, more than any package has.
const maxQueryPages = 10

// Query returns every advisory of a package, whatever its version, in full.
func (c *Client) Query(ctx context.Context, pkg Package) ([]Vuln, error) {
	var out []Vuln
	token := ""
	for range maxQueryPages {
		body := map[string]any{"package": pkg}
		if token != "" {
			body["page_token"] = token
		}
		var resp struct {
			Vulns         []json.RawMessage `json:"vulns"`
			NextPageToken string            `json:"next_page_token"`
		}
		if err := c.do(ctx, http.MethodPost, "/v1/query", body, &resp); err != nil {
			return nil, err
		}
		for _, raw := range resp.Vulns {
			var v Vuln
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("decode osv vuln: %w", err)
			}
			v.Raw = raw
			out = append(out, v)
		}
		if token = resp.NextPageToken; token == "" {
			return out, nil
		}
	}
	return nil, fmt.Errorf("osv query: more than %d pages of results", maxQueryPages)
}

// Vuln fetches the full record of a vulnerability.
func (c *Client) Vuln(ctx context.Context, id string) (Vuln, error) {
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &raw); err != nil {
		return Vuln{}, err
	}
	var v Vuln
	if err := json.Unmarshal(raw, &v); err != nil {
		return Vuln{}, fmt.Errorf("decode osv vuln %s: %w", id, err)
	}
	v.Raw = raw
	return v, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("osv %s: %w", path, err)
	}
	defer resp.Body.Close()
	// SECURITY: never read an unbounded response from the network.
	limited := io.LimitReader(resp.Body, maxBody)
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(limited, 512))
		return fmt.Errorf("osv %s: status %d: %s", path, resp.StatusCode, bytes.TrimSpace(snippet))
	}
	if err := json.NewDecoder(limited).Decode(out); err != nil {
		return fmt.Errorf("osv %s: decode: %w", path, err)
	}
	return nil
}

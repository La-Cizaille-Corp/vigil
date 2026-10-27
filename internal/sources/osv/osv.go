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

	Raw json.RawMessage `json:"-"`
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

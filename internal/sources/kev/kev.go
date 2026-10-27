// Package kev downloads the CISA Known Exploited Vulnerabilities catalogue.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
)

// DefaultURL is the official JSON feed.
const DefaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

const maxBody = 32 << 20

// Entry is one exploited CVE.
type Entry struct {
	CVE     string `json:"cveID"`
	DueDate string `json:"dueDate"`
}

// Fetch returns the catalogue indexed by CVE identifier.
func Fetch(ctx context.Context, client *http.Client, url, userAgent string) (map[string]Entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev: status %d", resp.StatusCode)
	}
	body, err := netsafe.ReadLimited(resp.Body, maxBody)
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	var doc struct {
		Vulnerabilities []Entry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("kev: decode: %w", err)
	}
	out := make(map[string]Entry, len(doc.Vulnerabilities))
	for _, e := range doc.Vulnerabilities {
		out[e.CVE] = e
	}
	return out, nil
}

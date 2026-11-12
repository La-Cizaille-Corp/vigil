// Package kev downloads the CISA Known Exploited Vulnerabilities catalogue.
package kev

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/sources"
)

// DefaultURL is the official JSON feed.
const DefaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

const maxBody = 32 << 20

// Client downloads the catalogue.
type Client struct {
	URL       string // empty: DefaultURL
	HTTP      *http.Client
	UserAgent string
}

// Entry is one exploited CVE.
type Entry struct {
	CVE     string `json:"cveID"`
	DueDate string `json:"dueDate"`
}

// Catalogue returns the catalogue indexed by CVE identifier.
func (c *Client) Catalogue(ctx context.Context) (map[string]Entry, error) {
	var doc struct {
		Vulnerabilities []Entry `json:"vulnerabilities"`
	}
	req, err := sources.NewRequest(ctx, http.MethodGet, cmp.Or(c.URL, DefaultURL), c.UserAgent, nil)
	if err == nil {
		err = sources.Do(c.HTTP, req, maxBody, &doc)
	}
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	out := make(map[string]Entry, len(doc.Vulnerabilities))
	for _, e := range doc.Vulnerabilities {
		// SECURITY: the due date is stored and shown; anything but a date is
		// dropped, the CVE stays listed.
		if _, err := time.Parse(time.DateOnly, e.DueDate); err != nil {
			e.DueDate = ""
		}
		out[e.CVE] = e
	}
	return out, nil
}

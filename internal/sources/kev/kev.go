// Package kev downloads the CISA Known Exploited Vulnerabilities catalogue.
package kev

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/sources"
)

// defaultURL is the official JSON feed.
const defaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

const maxBody = 32 << 20

// Client downloads the catalogue.
type Client struct {
	URL       string // empty: defaultURL
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
	err := sources.Get(ctx, c.HTTP, cmp.Or(c.URL, defaultURL), c.UserAgent, sources.Delays(c.URL, defaultURL, nil), maxBody, &doc)
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	// SECURITY: the catalogue lists more than a thousand CVEs and only grows;
	// an empty one is an answer the client cannot read (a field renamed), and
	// taken as it is, it would clear the KEV mark of every vulnerability.
	if len(doc.Vulnerabilities) == 0 {
		return nil, errors.New("kev: réponse illisible : catalogue vide")
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

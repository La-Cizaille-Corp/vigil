// Package epss queries the FIRST Exploit Prediction Scoring System API.
package epss

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/sources"
)

// DefaultURL is the public API endpoint.
const DefaultURL = "https://api.first.org/data/v1/epss"

// batchSize keeps the query string well below URL length limits.
const batchSize = 100

const maxBody = 4 << 20

// Client queries the API.
type Client struct {
	URL       string // empty: DefaultURL
	HTTP      *http.Client
	UserAgent string
}

// Scores returns the EPSS probability (0..1) of each CVE known to FIRST.
func (c *Client) Scores(ctx context.Context, cves []string) (map[string]float64, error) {
	out := make(map[string]float64, len(cves))
	for start := 0; start < len(cves); start += batchSize {
		end := min(start+batchSize, len(cves))
		var doc struct {
			Data *[]struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		u := cmp.Or(c.URL, DefaultURL) + "?cve=" + url.QueryEscape(strings.Join(cves[start:end], ","))
		req, err := sources.NewRequest(ctx, http.MethodGet, u, c.UserAgent, nil)
		if err == nil {
			err = sources.Do(c.HTTP, req, maxBody, &doc)
		}
		if err != nil {
			return nil, fmt.Errorf("epss: %w", err)
		}
		// SECURITY: an empty list is an answer (CVEs that FIRST does not score
		// yet), but no list at all is a format the client cannot read: taken
		// for no score, it would clear the EPSS score of every vulnerability.
		if doc.Data == nil {
			return nil, errors.New("epss: réponse illisible : liste « data » absente")
		}
		for _, d := range *doc.Data {
			// A probability: anything else (NaN, out of range) is ignored
			// rather than stored.
			if p, err := strconv.ParseFloat(d.EPSS, 64); err == nil && p >= 0 && p <= 1 {
				out[d.CVE] = p
			}
		}
	}
	return out, nil
}

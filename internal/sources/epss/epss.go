// Package epss queries the FIRST Exploit Prediction Scoring System API.
package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
)

// DefaultURL is the public API endpoint.
const DefaultURL = "https://api.first.org/data/v1/epss"

// batchSize keeps the query string well below URL length limits.
const batchSize = 100

const maxBody = 4 << 20

// Scores returns the EPSS probability (0..1) of each CVE known to FIRST.
func Scores(ctx context.Context, client *http.Client, endpoint, userAgent string, cves []string) (map[string]float64, error) {
	out := make(map[string]float64, len(cves))
	for start := 0; start < len(cves); start += batchSize {
		end := min(start+batchSize, len(cves))
		u := endpoint + "?cve=" + url.QueryEscape(strings.Join(cves[start:end], ","))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("epss: %w", err)
		}
		body, err := netsafe.ReadLimited(resp.Body, maxBody)
		_ = resp.Body.Close() // body fully read
		if err != nil {
			return nil, fmt.Errorf("epss: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("epss: status %d", resp.StatusCode)
		}
		var doc struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("epss: decode: %w", err)
		}
		for _, d := range doc.Data {
			// A probability: anything else (NaN, out of range) is ignored
			// rather than stored.
			if p, err := strconv.ParseFloat(d.EPSS, 64); err == nil && p >= 0 && p <= 1 {
				out[d.CVE] = p
			}
		}
	}
	return out, nil
}

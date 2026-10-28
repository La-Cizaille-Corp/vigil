package nvd

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

// DefaultCPEURL is the public CPE dictionary API.
const DefaultCPEURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

// maxCPEBody bounds a dictionary search response.
const maxCPEBody = 8 << 20

// Product is an entry of the CPE dictionary.
type Product struct {
	CPE     string // CPE 2.3 name
	Title   string // English title, e.g. "Fortinet FortiOS 7.2.4"
	Part    string // a (application), o (operating system), h (hardware)
	Vendor  string
	Name    string // product field of the CPE
	Version string // "*" or "-" when the entry covers no single version
}

// SearchCPE looks up the dictionary entries whose title or name contains
// every word of keywords; deprecated entries are left out.
func (c *Client) SearchCPE(ctx context.Context, keywords string, limit int) ([]Product, error) {
	base := c.CPEURL
	if base == "" {
		base = DefaultCPEURL
	}
	q := url.Values{"keywordSearch": {keywords}, "resultsPerPage": {strconv.Itoa(limit)}}
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd : HTTP %d (limite de requêtes atteinte ? réessayez dans 30 secondes)", resp.StatusCode)
	}
	data, err := netsafe.ReadLimited(resp.Body, maxCPEBody)
	if err != nil {
		return nil, fmt.Errorf("nvd: %w", err)
	}
	var r struct {
		Products []struct {
			CPE struct {
				Name       string `json:"cpeName"`
				Deprecated bool   `json:"deprecated"`
				Titles     []struct {
					Title string `json:"title"`
					Lang  string `json:"lang"`
				} `json:"titles"`
			} `json:"cpe"`
		} `json:"products"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("nvd: réponse illisible : %w", err)
	}
	var out []Product
	for _, p := range r.Products {
		if p.CPE.Deprecated {
			continue
		}
		fields := strings.Split(p.CPE.Name, ":")
		if len(fields) < 6 || fields[0] != "cpe" || fields[1] != "2.3" {
			continue
		}
		prod := Product{CPE: p.CPE.Name, Part: fields[2], Vendor: fields[3], Name: fields[4], Version: fields[5]}
		for _, t := range p.CPE.Titles {
			if prod.Title == "" || t.Lang == "en" {
				prod.Title = t.Title
			}
		}
		out = append(out, prod)
	}
	return out, nil
}

// WholeProduct returns the CPE name covering every version of p.
func (p Product) WholeProduct() string {
	return strings.Join([]string{"cpe", "2.3", p.Part, p.Vendor, p.Name, "*", "*", "*", "*", "*", "*", "*", "*"}, ":")
}

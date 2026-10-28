package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
)

// DefaultCPEURL is the public CPE dictionary API.
const DefaultCPEURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

const (
	// maxCPEBody bounds a dictionary response (a product such as the Linux
	// kernel has thousands of entries).
	maxCPEBody = 48 << 20
	// maxProductEntries is the most entries read for one product name.
	maxProductEntries = 10000
	// vendorEntries is how many of the newest entries of a vendor are read:
	// enough to list its current products.
	vendorEntries = 2000
	// keywordEntries is how many of the newest entries a keyword search keeps.
	keywordEntries = 200
)

// Product is an entry of the CPE dictionary.
type Product struct {
	CPE     string // CPE 2.3 name
	Title   string // English title, e.g. "Fortinet FortiOS 7.2.4"
	Part    string // a (application), o (operating system), h (hardware)
	Vendor  string
	Name    string    // product field of the CPE
	Version string    // "*" or "-" when the entry covers no single version
	Variant bool      // update, edition or language set: a variant of the version
	Created time.Time // when the entry was added to the dictionary
}

// SplitQuery separates the words of a search from its version numbers
// (words starting with a digit), lower case.
func SplitQuery(q string) (words, versions []string) {
	for _, f := range strings.Fields(strings.ToLower(q)) {
		if f[0] >= '0' && f[0] <= '9' {
			versions = append(versions, f)
		} else {
			words = append(words, f)
		}
	}
	return words, versions
}

// SearchCPE looks a product or a vendor up in the dictionary. The API
// returns entries oldest first, so a plain keyword search mostly finds
// products renamed long ago (elasticsearch:elasticsearch, last version 2015,
// instead of elastic:elasticsearch). The words are tried in turn as an exact
// product name, which finds every vendor name of the product with all its
// versions; as a vendor and a product; as a vendor alone; only then as
// keywords, keeping the newest entries.
func (c *Client) SearchCPE(ctx context.Context, query string) ([]Product, error) {
	words, _ := SplitQuery(query)
	for _, m := range matchStrings(words) {
		products, err := c.newestCPE(ctx, url.Values{"cpeMatchString": {m.pattern}}, m.entries)
		if err != nil || len(products) > 0 {
			return products, err
		}
	}
	return c.newestCPE(ctx, url.Values{"keywordSearch": {query}}, keywordEntries)
}

type match struct {
	pattern string
	entries int // newest entries read
}

// matchStrings are the CPE patterns tried for the words of a search:
// "exchange server" → product exchange_server; "fortinet fortios" → product
// fortinet_fortios, then vendor fortinet and product fortios, then product
// fortios; "fortinet" → product fortinet, then vendor fortinet. Words that a
// CPE name cannot hold as is are left to the keyword search.
func matchStrings(words []string) []match {
	for _, w := range words {
		for _, r := range w {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
				return nil
			}
		}
	}
	join := func(ws []string) string { return strings.Join(ws, "_") }
	switch len(words) {
	case 0:
		return nil
	case 1:
		return []match{{"cpe:2.3:*:*:" + words[0], maxProductEntries}, {"cpe:2.3:*:" + words[0], vendorEntries}}
	}
	return []match{
		{"cpe:2.3:*:*:" + join(words), maxProductEntries},
		{"cpe:2.3:*:" + words[0] + ":" + join(words[1:]), maxProductEntries},
		{"cpe:2.3:*:*:" + join(words[1:]), maxProductEntries},
	}
}

// newestCPE returns the n most recently added entries matching params: the
// first page tells the total, and the last page is read when there are more.
func (c *Client) newestCPE(ctx context.Context, params url.Values, n int) ([]Product, error) {
	params.Set("resultsPerPage", strconv.Itoa(n))
	products, total, err := c.cpePage(ctx, params)
	if err != nil || total <= n {
		return products, err
	}
	params.Set("startIndex", strconv.Itoa(total-n))
	products, _, err = c.cpePage(ctx, params)
	return products, err
}

func (c *Client) cpePage(ctx context.Context, params url.Values) ([]Product, int, error) {
	base := c.CPEURL
	if base == "" {
		base = DefaultCPEURL
	}
	if err := c.wait(ctx); err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+params.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("nvd: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("nvd : HTTP %d (limite de requêtes atteinte ? réessayez dans 30 secondes)", resp.StatusCode)
	}
	data, err := netsafe.ReadLimited(resp.Body, maxCPEBody)
	if err != nil {
		return nil, 0, fmt.Errorf("nvd: %w", err)
	}
	var r struct {
		TotalResults int `json:"totalResults"`
		Products     []struct {
			CPE struct {
				Name       string `json:"cpeName"`
				Deprecated bool   `json:"deprecated"`
				Created    string `json:"created"`
				Titles     []struct {
					Title string `json:"title"`
					Lang  string `json:"lang"`
				} `json:"titles"`
			} `json:"cpe"`
		} `json:"products"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, 0, fmt.Errorf("nvd: réponse illisible : %w", err)
	}
	var out []Product
	for _, p := range r.Products {
		if p.CPE.Deprecated {
			continue
		}
		fields := strings.Split(p.CPE.Name, ":")
		if len(fields) < 13 || fields[0] != "cpe" || fields[1] != "2.3" {
			continue
		}
		prod := Product{CPE: p.CPE.Name, Part: fields[2], Vendor: fields[3], Name: fields[4], Version: fields[5]}
		for _, f := range fields[6:9] { // update, edition, language
			prod.Variant = prod.Variant || (f != "*" && f != "-")
		}
		prod.Created, _ = time.Parse("2006-01-02T15:04:05", strings.TrimSuffix(strings.Split(p.CPE.Created, ".")[0], "Z"))
		for _, t := range p.CPE.Titles {
			if prod.Title == "" || t.Lang == "en" {
				prod.Title = t.Title
			}
		}
		out = append(out, prod)
	}
	return out, r.TotalResults, nil
}

// WholeProduct returns the CPE name covering every version of p.
func (p Product) WholeProduct() string {
	return strings.Join([]string{"cpe", "2.3", p.Part, p.Vendor, p.Name, "*", "*", "*", "*", "*", "*", "*", "*"}, ":")
}

// WholeVendor returns the CPE name covering every product of a vendor, of
// any kind (application, operating system, hardware).
func WholeVendor(vendor string) string {
	return "cpe:2.3:*:" + vendor + ":*:*:*:*:*:*:*:*:*"
}

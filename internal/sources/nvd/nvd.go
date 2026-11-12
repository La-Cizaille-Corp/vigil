// Package nvd is a minimal client for the NVD CVE API 2.0
// (https://nvd.nist.gov/developers/vulnerabilities), used for products that
// are identified by a CPE rather than a package URL.
package nvd

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
	"github.com/La-Cizaille-Corp/vigil/internal/sources"
)

// DefaultURL is the public CVE API.
const DefaultURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

const (
	// maxBody bounds a page of pageSize records, read whole: a record carries
	// its configurations, sometimes hundreds of CPE. The heaviest real page is
	// not measured, hence the margin.
	maxBody  = 64 << 20
	pageSize = 2000
	// maxDateRange is the longest publication date range the NVD accepts.
	maxDateRange = 120 * 24 * time.Hour
	// maxDateRanges bounds the requests made for a tracked period; a longer
	// period is fetched whole (Since is then applied by the caller).
	maxDateRanges = 6
	dateFormat    = "2006-01-02T15:04:05.000Z"
)

// Client queries the NVD. Without an API key the NVD allows 5 requests per
// 30 seconds, with one 50: the client spaces its requests accordingly.
type Client struct {
	URL       string // CVE API, empty: DefaultURL
	HTTP      *http.Client
	UserAgent string
	APIKey    string // optional
	CPEURL    string // CPE dictionary API, empty: DefaultCPEURL

	mu   sync.Mutex // spaces requests made by syncs and CPE searches alike
	last time.Time
}

// CVE is the subset of an NVD record that Vigil stores.
type CVE struct {
	ID          string
	Description string
	Severity    string  // CRITICAL, HIGH, MEDIUM, LOW or ""
	CVSS        float64 // base score of the most recent CVSS version, -1 if none
	Published   string
	Modified    string
	Refs        []string
	Raw         json.RawMessage
}

// productCPE splits a CPE 2.3 name and reports whether it designates a whole
// product (version "*" or "-") rather than one release.
func productCPE(cpe string) (fields []string, wholeProduct bool, err error) {
	fields, ok := SplitCPE(cpe)
	if !ok {
		return nil, false, fmt.Errorf("CPE 2.3 invalide : %q", cpe)
	}
	return fields, fields[5] == "*" || fields[5] == "-", nil
}

// Query describes how a product is tracked.
type Query struct {
	CPE     string
	Version string // asset version, used when the CPE version is a wildcard
	// Mode: "" the asset version (every version without any), "all" every
	// version of the product, "from" versions >= From.
	Mode string
	From string
	// Since, when set, limits the CVEs to those published since then, plus
	// those listed in CISA KEV whatever their date.
	Since time.Time
}

// withVersion fills the version of a CPE when it is a wildcard, unless the
// CPE covers every product of a vendor.
func withVersion(cpe, version string) string {
	fields, whole, err := productCPE(cpe)
	if err != nil || !whole || version == "" || strings.ContainsAny(version, ":*?") || fields[4] == "*" {
		return cpe
	}
	fields[5] = version
	return strings.Join(fields, ":")
}

// productWide replaces the version of a CPE with a wildcard.
func productWide(fields []string) string {
	f := slices.Clone(fields)
	f[5] = "*"
	return strings.Join(f, ":")
}

// ForCPE returns the CVEs matching a query. For an exact version the NVD
// matches the affected version ranges itself.
func (c *Client) ForCPE(ctx context.Context, query Query) ([]CVE, error) {
	cpe := withVersion(query.CPE, query.Version)
	fields, whole, err := productCPE(cpe)
	if err != nil {
		return nil, err
	}
	mode := query.Mode
	if (mode == "" && whole) || fields[4] == "*" {
		mode = "all" // a whole product, or every product of a vendor
	}
	q := url.Values{}
	switch mode {
	case "":
		q.Set("cpeName", cpe)
	case "all":
		q.Set("virtualMatchString", productWide(fields))
	case "from":
		if query.From == "" {
			return nil, errors.New("version de départ manquante")
		}
		q.Set("virtualMatchString", productWide(fields))
		q.Set("versionStart", query.From)
		q.Set("versionStartType", "including")
	default:
		return nil, fmt.Errorf("mode de suivi NVD inconnu : %q", mode)
	}
	q.Set("resultsPerPage", fmt.Sprint(pageSize))
	return c.search(ctx, q, query.Since)
}

// ForKeyword returns the CVEs whose description holds phrase (any case),
// published since `since` plus those listed in CISA KEV, or all of them
// when since is zero.
func (c *Client) ForKeyword(ctx context.Context, phrase string, since time.Time) ([]CVE, error) {
	if strings.TrimSpace(phrase) == "" {
		return nil, errors.New("recherche vide")
	}
	q := url.Values{}
	q.Set("keywordSearch", phrase)
	q.Set("keywordExactMatch", "")
	q.Set("resultsPerPage", fmt.Sprint(pageSize))
	return c.search(ctx, q, since)
}

// search runs q over the publication period starting at since.
func (c *Client) search(ctx context.Context, q url.Values, since time.Time) ([]CVE, error) {
	end := time.Now().UTC()
	if since.IsZero() || end.Sub(since) > maxDateRanges*maxDateRange {
		return c.pages(ctx, q)
	}
	// The NVD only accepts 120-day ranges: one request per range, plus one
	// for the exploited CVEs published before the period.
	var out []CVE
	seen := map[string]bool{}
	add := func(list []CVE) {
		for _, cve := range list {
			if !seen[cve.ID] {
				seen[cve.ID] = true
				out = append(out, cve)
			}
		}
	}
	for from := since.UTC(); from.Before(end); from = from.Add(maxDateRange) {
		to := from.Add(maxDateRange)
		if to.After(end) {
			to = end
		}
		r := cloneValues(q)
		r.Set("pubStartDate", from.Format(dateFormat))
		r.Set("pubEndDate", to.Format(dateFormat))
		list, err := c.pages(ctx, r)
		if err != nil {
			return nil, err
		}
		add(list)
	}
	r := cloneValues(q)
	r.Set("hasKev", "")
	list, err := c.pages(ctx, r)
	if err != nil {
		return nil, err
	}
	add(list)
	return out, nil
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v)+2)
	for k, list := range v {
		out[k] = slices.Clone(list)
	}
	return out
}

// maxPages bounds a query: 100 000 vulnerabilities, more than any real
// product, so that a wrong totalResults cannot stall the synchronisation.
const maxPages = 50

// pages fetches every page of results of q.
func (c *Client) pages(ctx context.Context, q url.Values) ([]CVE, error) {
	var out []CVE
	for start, n := 0, 0; ; start, n = start+pageSize, n+1 {
		if n == maxPages {
			return nil, fmt.Errorf("nvd: more than %d pages of results", maxPages)
		}
		q.Set("startIndex", fmt.Sprint(start))
		page, total, err := c.get(ctx, q)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if start+pageSize >= total || len(page) == 0 {
			return out, nil
		}
	}
}

// retryDelays are the waits before asking again after a temporary failure:
// the NVD often answers 503 for a moment, and one failed request out of the
// several of an asset would leave it unchecked.
var retryDelays = []time.Duration{10 * time.Second, 30 * time.Second}

// public reports whether the client asks the NVD itself, whose rate limit it
// respects; a mirror or a test server is asked without waiting.
func (c *Client) public() bool { return cmp.Or(c.URL, DefaultURL) == DefaultURL }

// rateLimited reports whether the NVD refused a request for its rate limit:
// it answers 403, sometimes 429.
func rateLimited(err error) bool {
	var status *sources.StatusError
	return errors.As(err, &status) && (status.Code == http.StatusForbidden || status.Code == http.StatusTooManyRequests)
}

// get fetches a page of results, asked again after a temporary failure.
// SECURITY: a 404 does not mean "no CVE", it is an error like any answer other
// than 200 (sources.StatusError). The NVD answers it to a refused API key
// ("Invalid apiKey."), while an unknown CPE name gets a 200 without results.
// Read as an empty answer, it would mark every open finding of the assets
// tracked through the NVD as fixed.
func (c *Client) get(ctx context.Context, q url.Values) ([]CVE, int, error) {
	delays := retryDelays
	if !c.public() {
		delays = make([]time.Duration, len(retryDelays)) // tests and mirrors
	}
	var r response
	err := sources.Retry(ctx, delays, func() (bool, error) {
		err := c.send(ctx, cmp.Or(c.URL, DefaultURL)+"?"+q.Encode(), maxBody, &r)
		return rateLimited(err) || sources.Temporary(err), err
	})
	if err != nil {
		return nil, 0, err
	}
	cves, err := parse(r)
	return cves, r.TotalResults, err
}

// send waits its turn, then asks the NVD and decodes its answer into out.
func (c *Client) send(ctx context.Context, url string, max int64, out any) error {
	if err := c.wait(ctx); err != nil {
		return err
	}
	req, err := sources.NewRequest(ctx, http.MethodGet, url, c.UserAgent, nil)
	if err == nil {
		if c.APIKey != "" {
			req.Header.Set("apiKey", c.APIKey)
		}
		err = sources.Do(c.HTTP, req, max, out)
	}
	if err != nil {
		return fmt.Errorf("nvd: %w", err)
	}
	return nil
}

// wait spaces requests to respect the NVD rate limit.
func (c *Client) wait(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	gap := 6500 * time.Millisecond
	if c.APIKey != "" {
		gap = 700 * time.Millisecond
	}
	if !c.public() {
		gap = 0 // tests and mirrors
	}
	if err := sources.Sleep(ctx, time.Until(c.last.Add(gap))); err != nil {
		return err
	}
	c.last = time.Now()
	return nil
}

type response struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE json.RawMessage `json:"cve"`
	} `json:"vulnerabilities"`
}

type record struct {
	ID           string `json:"id"`
	VulnStatus   string `json:"vulnStatus"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics map[string][]struct {
		CVSSData struct {
			BaseSeverity string  `json:"baseSeverity"`
			BaseScore    float64 `json:"baseScore"`
		} `json:"cvssData"`
		BaseSeverity string `json:"baseSeverity"` // CVSS v2 puts it here
	} `json:"metrics"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

// parse keeps the records of a page that are not rejected. SECURITY: a page
// without its list, or a record that cannot be read, is an error, like a 404
// (see get): left out, its CVE would no longer be reported, and its findings
// would be marked fixed. A field of the NVD that changes type would do it to
// every record.
func parse(r response) ([]CVE, error) {
	if r.Vulnerabilities == nil {
		return nil, errors.New("nvd: réponse illisible : liste « vulnerabilities » absente")
	}
	out := make([]CVE, 0, len(r.Vulnerabilities))
	for i, v := range r.Vulnerabilities {
		var rec record
		if err := json.Unmarshal(v.CVE, &rec); err != nil {
			return nil, fmt.Errorf("nvd: réponse illisible : enregistrement %d : %w", i+1, err)
		}
		if rec.ID == "" {
			return nil, fmt.Errorf("nvd: réponse illisible : enregistrement %d sans identifiant", i+1)
		}
		if rec.VulnStatus == "Rejected" {
			continue
		}
		c := CVE{CVSS: -1, ID: rec.ID, Published: rec.Published, Modified: rec.LastModified, Raw: v.CVE}
		for _, d := range rec.Descriptions {
			if d.Lang == "en" {
				c.Description = d.Value
			}
		}
		// Most recent CVSS version first.
		for _, key := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
			if m := rec.Metrics[key]; len(m) > 0 {
				c.Severity = strings.ToUpper(cmp.Or(m[0].CVSSData.BaseSeverity, m[0].BaseSeverity))
				c.CVSS = m[0].CVSSData.BaseScore
				break
			}
		}
		for _, ref := range rec.References {
			if u, ok := netsafe.WebURL(ref.URL); ok {
				c.Refs = append(c.Refs, u)
			}
		}
		out = append(out, c)
	}
	return out, nil
}

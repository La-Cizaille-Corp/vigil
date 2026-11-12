// Package sources holds what the clients of the vulnerability sources (OSV, the
// NVD, CISA KEV, FIRST EPSS) share: a request is made, its answer checked, read
// within a bound and decoded the same way for all, and a temporary failure is
// tried again.
//
// Every client has the same form: URL, the address of the API (empty for the
// public one, its DefaultURL), HTTP, the client given by main with its time
// limit and redirect policy, and UserAgent.
package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/netsafe"
)

// NewRequest returns a request made by the client named userAgent. A body
// other than nil is sent as JSON, the format of every source.
func NewRequest(ctx context.Context, method, url, userAgent string, body any) (*http.Request, error) {
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// StatusError is an answer other than 200 OK. SECURITY: every other status is
// a failure, a 404 included: the NVD answers it to a refused API key, and read
// as "nothing found" it would mark open findings as fixed.
type StatusError struct {
	Code   int
	Reason string // what the source says of it, if anything (see reason)
}

func (e *StatusError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("HTTP %d", e.Code)
	}
	return fmt.Sprintf("HTTP %d (%s)", e.Code, e.Reason)
}

// netError is a failure of the network, on the way there or back: the same
// request may succeed if sent again.
type netError struct{ err error }

func (e *netError) Error() string { return e.err.Error() }
func (e *netError) Unwrap() error { return e.err }

// Temporary reports whether a request that failed with err (from Open or Do)
// may succeed if sent again: the network failed, or the source answered 429
// (too many requests) or 5xx. A refusal, a redirect refused by
// netsafe.CheckRedirect, an answer too large or unreadable would fail the
// same way.
func Temporary(err error) bool {
	var status *StatusError
	if errors.As(err, &status) {
		return status.Code == http.StatusTooManyRequests || status.Code >= 500
	}
	var network *netError
	return errors.As(err, &network)
}

// cutReader makes a failure of reading a body a *netError, so that Temporary
// tells it from a malformed answer: the connection was cut or closed (an
// HTTP/2 GOAWAY, a body shorter than announced), or the time limit came while
// reading. The end of the body and a body past its bound are left as they are.
type cutReader struct{ r io.Reader }

func (c cutReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	var tooLarge *netsafe.TooLargeError
	if err != nil && err != io.EOF && !errors.As(err, &tooLarge) {
		err = &netError{err}
	}
	return n, err
}

// Open sends req with c and returns the body of the answer, which the caller
// closes. SECURITY: never an unbounded read from the network: past max bytes,
// reading the body fails with a *netsafe.TooLargeError instead of ending as if
// the answer were whole. An answer other than 200 OK is a *StatusError. A
// reading cut short fails with an error that Temporary accepts.
func Open(c *http.Client, req *http.Request, max int64) (io.ReadCloser, error) {
	// #nosec G704 -- req is made by NewRequest for the fixed address of a
	// source; it is not an incoming request, whose URL a user would choose.
	resp, err := c.Do(req)
	if errors.As(err, new(*netsafe.RedirectError)) {
		return nil, err // refused by the policy of the client, not by the network
	}
	if err != nil {
		return nil, &netError{err}
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, &StatusError{Code: resp.StatusCode, Reason: reason(resp)}
	}
	return struct {
		io.Reader
		io.Closer
	}{cutReader{netsafe.LimitReader(resp.Body, max)}, resp.Body}, nil
}

// Do sends req with c and decodes the JSON answer into out, read whole and at
// most max bytes. Its errors are those of Open, or a reading cut short, or an
// answer that is not the JSON expected.
func Do(c *http.Client, req *http.Request, max int64, out any) error {
	body, err := Open(c, req, max)
	if err != nil {
		return err
	}
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		return err // too large, or cut short (a *netError, see cutReader)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("réponse illisible : %w", err)
	}
	return nil
}

// maxReason bounds what is read of a refusal to find its reason; a longer one
// is cut and then gives none.
const maxReason = 64 << 10

// reason is what a source says of a refusal, for the error shown to the
// operator: the "message" header of the NVD ("Invalid apiKey."), or else the
// "message" field of a JSON answer, as OSV gives it. SECURITY: one line of
// printable text, 200 characters at most, never the raw answer.
func reason(resp *http.Response) string {
	m := resp.Header.Get("message")
	if m == "" {
		var doc struct {
			Message string `json:"message"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, maxReason)).Decode(&doc) == nil {
			m = doc.Message
		}
	}
	words := strings.FieldsFunc(m, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) })
	return clip.Text(strings.Join(words, " "), 200)
}

// Retry calls fn, and again after each of delays while it fails with a
// temporary error. It returns the last error, or that of ctx when ctx ends
// during a wait. Without delays, fn is called once.
func Retry(ctx context.Context, delays []time.Duration, fn func() (temporary bool, err error)) error {
	for attempt := 0; ; attempt++ {
		temporary, err := fn()
		if err == nil || !temporary || attempt == len(delays) || ctx.Err() != nil {
			return err
		}
		if err := Sleep(ctx, delays[attempt]); err != nil {
			return err
		}
	}
}

// Sleep waits for d, or less if ctx ends first, and then returns ctx.Err().
func Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
	return ctx.Err()
}

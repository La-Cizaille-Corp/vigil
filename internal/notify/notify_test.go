package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

func TestSendDigest(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	bodies := map[string]map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/broken-SECRET") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		bodies[r.URL.Path] = body
	}))
	defer srv.Close()
	for _, h := range []store.Webhook{
		{Digests: true, Name: "chat", Kind: "slack", URL: srv.URL + "/slack-SECRET", Enabled: true},
		{Digests: true, Name: "siem", Kind: "generic", URL: srv.URL + "/generic-SECRET", Enabled: true},
		{Digests: true, Name: "down", Kind: "teams", URL: srv.URL + "/broken-SECRET", Enabled: true},
		{Digests: true, Name: "off", Kind: "slack", URL: srv.URL + "/off-SECRET", Enabled: false},
	} {
		if _, err := st.CreateWebhook(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	n := &Notifier{Store: st, HTTP: srv.Client(), UserAgent: "test", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err = n.SendDigest(ctx, store.Digest{ID: 7, Markdown: "# Digest\nCVE-2021-44228"}, "https://vigil.example/digests/7")

	if err == nil || !strings.Contains(err.Error(), "down") {
		t.Fatalf("failure of one webhook not reported: %v", err)
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Errorf("webhook URL leaked in error: %v", err)
	}
	if text, _ := bodies["/slack-SECRET"]["text"].(string); !strings.Contains(text, "CVE-2021-44228") || !strings.Contains(text, "/digests/7") {
		t.Errorf("slack payload = %v", bodies["/slack-SECRET"])
	}
	if bodies["/generic-SECRET"]["event"] != "digest" || bodies["/generic-SECRET"]["digest_id"] != float64(7) {
		t.Errorf("generic payload = %v", bodies["/generic-SECRET"])
	}
	if _, called := bodies["/off-SECRET"]; called {
		t.Error("disabled webhook called")
	}
	hooks, _ := st.ListWebhooks(ctx)
	for _, h := range hooks {
		if (h.Name == "down") != (h.LastError != "") {
			t.Errorf("%s: last error %q", h.Name, h.LastError)
		}
	}
}

func TestValidateAndMask(t *testing.T) {
	if err := ValidateWebhook(store.Webhook{Name: "x", Kind: "irc", URL: "https://example.org/h"}); err == nil {
		t.Error("unknown kind accepted")
	}
	// Private addresses are refused at dial time (netsafe), not here.
	if err := ValidateWebhook(store.Webhook{Name: "x", Kind: "slack", URL: "http://example.org/h"}); err == nil {
		t.Error("clear-text URL accepted")
	}
	if got := MaskURL("https://hooks.slack.com/services/T0/B0/secret"); got != "https://hooks.slack.com/…" {
		t.Errorf("MaskURL = %q", got)
	}
}

// A digest longer than chat platforms accept is cut once, keeping the
// truncation note and the link, without splitting a UTF-8 character.
func TestLongDigestKeepsLink(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var text string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		text = body["text"]
	}))
	defer srv.Close()
	st.CreateWebhook(ctx, store.Webhook{Name: "chat", Kind: "slack", URL: srv.URL + "/h", Enabled: true, Digests: true})
	n := &Notifier{Store: st, HTTP: srv.Client(), UserAgent: "test", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	long := strings.Repeat("é", maxText) // 2 bytes each: twice the limit
	if err := n.SendDigest(ctx, store.Digest{ID: 9, Markdown: long}, "https://vigil.example/digests/9"); err != nil {
		t.Fatal(err)
	}
	if len(text) > maxText || !strings.HasSuffix(text, "https://vigil.example/digests/9") ||
		!strings.Contains(text, "tronqué") || !utf8.ValidString(text) {
		t.Errorf("digest message: %d bytes, ends with %q", len(text), text[max(0, len(text)-60):])
	}
}

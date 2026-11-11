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
		{Digests: true, Name: "down", Kind: "mattermost", URL: srv.URL + "/broken-SECRET", Enabled: true},
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
	// The name is measured in characters, as the form says (R2).
	for n, ok := range map[int]bool{100: true, 101: false} {
		err := ValidateWebhook(store.Webhook{Name: strings.Repeat("é", n), Kind: "slack", URL: "https://example.org/h"})
		if (err == nil) != ok {
			t.Errorf("name of %d accented characters: %v", n, err)
		}
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

// Text from sources and SBOMs cannot ping a channel nor hide a link in an
// alert.
func TestAlertNeutralisesMarkup(t *testing.T) {
	n := &Notifier{BaseURL: "https://vigil.example"}
	m := n.alertMessage([]store.Alert{{Finding: store.Finding{ID: 1, VulnID: "CVE-2026-1", Severity: "CRITICAL",
		AssetName: "app <!channel>", Summary: "@here [Correctif](https://evil.example)"}}})
	for _, bad := range []string{"<!channel>", "@here", "](https://evil"} {
		if strings.Contains(m.Text, bad) {
			t.Errorf("%q survives in %q", bad, m.Text)
		}
	}
}

// Teams gets an Adaptive Card, at the address exactly as it was given: its
// signature is checked on the query string.
func TestTeamsCard(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var query string
	var body struct {
		Type        string `json:"type"`
		Attachments []struct {
			ContentType string `json:"contentType"`
			Content     struct {
				Type string `json:"type"`
				Body []struct {
					Type string `json:"type"`
					Text string `json:"text"`
					Wrap bool   `json:"wrap"`
				} `json:"body"`
			} `json:"content"`
		} `json:"attachments"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		json.NewDecoder(r.Body).Decode(&body)
	}))
	defer srv.Close()
	const signed = "api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=a%2Bb-c_d"
	h := store.Webhook{Name: "Équipe", Kind: "teams", URL: srv.URL + "/workflows/1/invoke?" + signed, Enabled: true}
	if h.ID, err = st.CreateWebhook(ctx, h); err != nil {
		t.Fatal(err)
	}
	n := &Notifier{Store: st, HTTP: srv.Client(), UserAgent: "test", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := n.SendTest(ctx, h); err != nil {
		t.Fatal(err)
	}
	if query != signed {
		t.Errorf("query = %q, want %q", query, signed)
	}
	if body.Type != "message" || len(body.Attachments) != 1 || body.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("message = %+v", body)
	}
	card := body.Attachments[0].Content
	if card.Type != "AdaptiveCard" || len(card.Body) != 1 || !card.Body[0].Wrap || !strings.Contains(card.Body[0].Text, "test du canal") {
		t.Errorf("card = %+v", card)
	}
	if got := teamsCard(strings.Repeat("é", 40000)); len(mustJSON(t, got)) > 28<<10 {
		t.Errorf("a long card is %d bytes", len(mustJSON(t, got)))
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRefusal(t *testing.T) {
	teams := store.Webhook{Kind: "teams"}
	cases := []struct {
		name   string
		h      store.Webhook
		status int
		reply  string
		want   []string
		absent []string
	}{
		{"Teams, silent", teams, 401, "", []string{"réponse HTTP 401", "Tout le monde", "logic.azure.com"}, nil},
		{"Teams, a reason", teams, 401, `{"error":{"code":"DirectApiAuthorizationRequired","message":"The request must be authenticated."}}`,
			[]string{"DirectApiAuthorizationRequired", "must be authenticated", "Tout le monde"}, nil},
		{"Teams, another refusal", teams, 400, `{"code":"InvalidRequestContent","message":"Bad body."}`, []string{"InvalidRequestContent", "Bad body."}, []string{"Tout le monde"}},
		{"Slack", store.Webhook{Kind: "slack"}, 400, "invalid_payload", []string{"réponse HTTP 400 (invalid_payload)"}, []string{"Tout le monde"}},
		{"another channel, 401", store.Webhook{Kind: "slack"}, 401, "", []string{"réponse HTTP 401"}, []string{"Tout le monde"}},
		{"an HTML page", store.Webhook{Kind: "generic"}, 502, "<html>Bad Gateway</html>", []string{"réponse HTTP 502"}, []string{"html", "("}},
		{"an address", store.Webhook{Kind: "generic"}, 403, `{"message":"denied for https://hooks.example/SECRET"}`, []string{"réponse HTTP 403"}, []string{"SECRET"}},
		{"a signature", store.Webhook{Kind: "generic"}, 403, `sig=SECRET is wrong`, []string{"réponse HTTP 403"}, []string{"SECRET"}},
	}
	for _, c := range cases {
		got := refusal(c.h, c.status, []byte(c.reply)).Error()
		for _, want := range c.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s: %q misses %q", c.name, got, want)
			}
		}
		for _, absent := range c.absent {
			if strings.Contains(got, absent) {
				t.Errorf("%s: %q holds %q", c.name, got, absent)
			}
		}
	}
	if long := refusal(store.Webhook{}, 400, []byte(strings.Repeat("x", 5000))).Error(); len(long) > 300 {
		t.Errorf("long reason: %d bytes", len(long))
	}
}

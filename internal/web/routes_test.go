package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
)

// Every route but the static files goes through the route table: one
// registered directly on the mux would escape the policy and the matrix.
func TestRoutesGoThroughTheTable(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var direct []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				pattern, _ := strconv.Unquote(lit.Value)
				direct = append(direct, name+": "+pattern)
			}
			return true
		})
	}
	if want := []string{"server.go: GET /static/"}; !slices.Equal(direct, want) {
		t.Errorf("routes registered outside the table: %v, want %v", direct, want)
	}
}

// wantPolicy is the authorization policy of the UI: the least role of each
// route, or public for the routes reached without a session (first setup,
// sign-in and the token-authenticated API, which check their caller
// themselves). The static files (GET /static/) are mounted apart.
// SECURITY: it is written here apart from the route table, so that adding a
// route or changing its role means changing both, in a reviewed diff.
var wantPolicy = map[string]string{
	"GET /setup":   public,
	"POST /setup":  public,
	"GET /login":   public,
	"POST /login":  public,
	"POST /logout": auth.RoleViewer,

	"GET /account":               auth.RoleViewer,
	"POST /account/totp/start":   auth.RoleViewer,
	"POST /account/totp/confirm": auth.RoleViewer,
	"POST /account/totp/disable": auth.RoleViewer,
	"POST /account/password":     auth.RoleViewer,

	"POST /account/sessions/close-others": auth.RoleViewer,

	"GET /{$}":                   auth.RoleViewer,
	"GET /sync":                  auth.RoleViewer,
	"POST /sync":                 auth.RoleAnalyst,
	"GET /cti":                   auth.RoleViewer,
	"POST /cti/refresh":          auth.RoleAnalyst,
	"GET /digests":               auth.RoleViewer,
	"POST /digests":              auth.RoleAnalyst,
	"GET /digests/{id}":          auth.RoleViewer,
	"GET /digests/{id}/markdown": auth.RoleViewer,

	"GET /assets":                                auth.RoleViewer,
	"GET /assets.csv":                            auth.RoleViewer,
	"GET /assets/{id}":                           auth.RoleViewer,
	"GET /assets/new":                            auth.RoleAnalyst,
	"GET /assets/cpe":                            auth.RoleAnalyst,
	"POST /assets":                               auth.RoleAnalyst,
	"POST /assets/import":                        auth.RoleAnalyst,
	"POST /assets/import-csv":                    auth.RoleAnalyst,
	"POST /assets/{id}":                          auth.RoleAnalyst,
	"POST /assets/{id}/delete":                   auth.RoleAnalyst,
	"POST /assets/{id}/scan":                     auth.RoleAnalyst,
	"POST /assets/{id}/full-history":             auth.RoleAnalyst,
	"POST /assets/{id}/dismissals":               auth.RoleAnalyst,
	"POST /assets/{id}/dismissals/{rule}/delete": auth.RoleAnalyst,

	"GET /findings":       auth.RoleViewer,
	"GET /findings.csv":   auth.RoleViewer,
	"GET /findings/vex":   auth.RoleViewer,
	"GET /findings/{id}":  auth.RoleViewer,
	"POST /findings/bulk": auth.RoleAnalyst,
	"POST /findings/vex":  auth.RoleAnalyst,
	"POST /findings/{id}": auth.RoleAnalyst,

	"GET /settings":                        auth.RoleViewer,
	"GET /settings/watch":                  auth.RoleViewer,
	"POST /settings/watch":                 auth.RoleAnalyst,
	"GET /settings/feeds":                  auth.RoleViewer,
	"GET /settings/webhooks":               auth.RoleAdmin,
	"GET /settings/sla":                    auth.RoleAdmin,
	"GET /settings/tokens":                 auth.RoleAdmin,
	"POST /settings/news":                  auth.RoleAdmin,
	"POST /settings/sla":                   auth.RoleAdmin,
	"POST /settings/feeds":                 auth.RoleAdmin,
	"POST /settings/feeds/{id}":            auth.RoleAdmin,
	"POST /settings/feeds/{id}/toggle":     auth.RoleAdmin,
	"POST /settings/feeds/{id}/delete":     auth.RoleAdmin,
	"POST /settings/webhooks":              auth.RoleAdmin,
	"POST /settings/webhooks/{id}":         auth.RoleAdmin,
	"POST /settings/webhooks/{id}/toggle":  auth.RoleAdmin,
	"POST /settings/webhooks/{id}/test":    auth.RoleAdmin,
	"POST /settings/webhooks/{id}/delete":  auth.RoleAdmin,
	"POST /settings/tokens":                auth.RoleAdmin,
	"POST /settings/tokens/{id}/delete":    auth.RoleAdmin,
	"GET /settings/audit":                  auth.RoleAdmin,
	"GET /settings/users":                  auth.RoleAdmin,
	"POST /settings/users":                 auth.RoleAdmin,
	"POST /settings/users/totp-policy":     auth.RoleAdmin,
	"POST /settings/users/{id}/role":       auth.RoleAdmin,
	"POST /settings/users/{id}/access":     auth.RoleAdmin,
	"GET /settings/groups":                 auth.RoleAdmin,
	"POST /settings/groups":                auth.RoleAdmin,
	"GET /settings/groups/{id}":            auth.RoleAdmin,
	"POST /settings/groups/{id}":           auth.RoleAdmin,
	"POST /settings/groups/{id}/rules":     auth.RoleAdmin,
	"POST /settings/groups/{id}/delete":    auth.RoleAdmin,
	"POST /settings/users/{id}/disable":    auth.RoleAdmin,
	"POST /settings/users/{id}/enable":     auth.RoleAdmin,
	"POST /settings/users/{id}/password":   auth.RoleAdmin,
	"POST /settings/users/{id}/totp-reset": auth.RoleAdmin,

	"PUT /api/v1/projects/{project}/sbom": public,
}

// TestRouteMatrix checks the route table against the policy above, then
// every protected route against every role: an anonymous request goes to the
// sign-in page, a lower role is refused even with a valid CSRF token, and a
// request that changes state is refused without its CSRF token for the roles
// allowed. A route added without its role, or with another one than the
// policy, fails here.
func TestRouteMatrix(t *testing.T) {
	routes := (&Server{}).routes()
	seen := map[string]bool{}
	for _, rt := range routes {
		seen[rt.pattern] = true
		if want, ok := wantPolicy[rt.pattern]; !ok {
			t.Errorf("%s (%s) is not in the policy", rt.pattern, rt.role)
		} else if rt.role != want {
			t.Errorf("%s requires %s, the policy says %s", rt.pattern, rt.role, want)
		}
	}
	for pattern := range wantPolicy {
		if !seen[pattern] {
			t.Errorf("%s is in the policy but not in the route table", pattern)
		}
	}

	st, base := newBareServer(t, nil)
	roles := []string{auth.RoleViewer, auth.RoleAnalyst, auth.RoleAdmin}
	users := map[string]*client{}
	tokens := map[string]string{}
	for _, role := range roles {
		addUser(t, st, role, role)
		users[role] = loginAs(t, base, role, testPassword)
		tokens[role] = users[role].csrf()
	}
	for _, rt := range routes {
		if rt.role == public {
			continue
		}
		method, path, _ := strings.Cut(rt.pattern, " ")
		path = strings.NewReplacer("{$}", "", "{id}", "1", "{rule}", "1").Replace(path)
		if code, to := newClient(t, base).send(method, path, nil); code != http.StatusSeeOther || to != "/login" {
			t.Errorf("%s anonymous: %d to %q, want 303 to /login", rt.pattern, code, to)
		}
		for _, role := range roles {
			c := users[role]
			if !auth.RoleAtLeast(role, rt.role) {
				if code, _ := c.send(method, path, url.Values{"csrf": {tokens[role]}}); code != http.StatusForbidden {
					t.Errorf("%s as %s: %d, want 403", rt.pattern, role, code)
				}
				continue
			}
			// Only refusals are checked: the handler of an allowed request
			// never runs, so that the matrix changes nothing.
			if method != http.MethodGet {
				if code, _ := c.send(method, path, nil); code != http.StatusForbidden {
					t.Errorf("%s as %s without CSRF token: %d, want 403", rt.pattern, role, code)
				}
			}
		}
	}
}

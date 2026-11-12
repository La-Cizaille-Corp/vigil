package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// webSources parses the non-test Go files of the package.
func webSources(t *testing.T) map[string]*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*ast.File{}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = f
	}
	return files
}

// Only scope.go may grant a scope, every asset or those of some groups: a
// handler that needs one asks it for the one of the request.
func TestEverythingOnlyInScopeFile(t *testing.T) {
	for name, f := range webSources(t) {
		if name == "scope.go" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Everything" || sel.Sel.Name == "InGroups") {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "store" {
					t.Errorf("%s uses store.%s: take readScope, writeScope, requestScope or listScope", name, sel.Sel.Name)
				}
			}
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Scope" && len(call.Args) == 0 {
					t.Errorf("%s takes the scope of an account: take readScope, writeScope, requestScope or listScope", name)
				}
			}
			return true
		})
	}
}

// The store methods of the synchronisation take no scope (see unscoped in
// package store): the UI must not call them.
func TestSystemMethodsStayOutOfWeb(t *testing.T) {
	system := []string{"ObserveFinding", "InTrackedPeriod", "AutoResolveStale", "SetOlderVulns", "ApplyDismissalRules",
		"UpsertVulnerability", "VulnModified", "SetExploitSignals", "ListVulnCVEs", "MarkAlerted", "CreateDigest", "LastDigestTime"}
	for name, f := range webSources(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && slices.Contains(system, sel.Sel.Name) {
				t.Errorf("%s calls %s, reserved to the synchronisation", name, sel.Sel.Name)
			}
			return true
		})
	}
}

// A request without a session has no scope: it sees nothing, whatever group
// it asks for.
func TestScopeWithoutSession(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		r := httptest.NewRequest(method, "/?group=1", nil)
		list, _ := listScope(r)
		for _, sc := range []store.Scope{readScope(r), writeScope(r), requestScope(r), list} {
			if !reflect.DeepEqual(sc, store.Scope{}) {
				t.Errorf("%s without a session: not the zero scope", method)
			}
		}
	}
}

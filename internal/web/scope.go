package web

import (
	"context"
	"net/http"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// The scope of a request is the part of the inventory it may read or change
// (A67): every call to the store about assets, findings or digests passes it.
// SECURITY: this file is the only one of package web that grants
// store.Everything; TestEverythingOnlyInScopeFile checks it.

// readScope is what the signed-in account may see. Every account sees every
// asset until accounts can be limited to groups; a request without a session
// sees nothing.
func readScope(r *http.Request) store.Scope {
	if _, ok := sessionFrom(r.Context()); !ok {
		return store.Scope{}
	}
	return store.Everything
}

// writeScope is what the signed-in account may change: the same as what it
// sees while roles are global, as the role of each route already says who
// may write.
func writeScope(r *http.Request) store.Scope { return readScope(r) }

// requestScope is the scope of an object loaded by its id: what the account
// may see for a page, what it may change for a form.
func requestScope(r *http.Request) store.Scope {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return readScope(r)
	}
	return writeScope(r)
}

// inScope binds a lookup of the inventory by id to the scope of the request
// (requestScope), for load.
func inScope[T any](r *http.Request, get func(context.Context, store.Scope, int64) (T, error)) func(context.Context, int64) (T, error) {
	return func(ctx context.Context, id int64) (T, error) { return get(ctx, requestScope(r), id) }
}

// tokenScope is what an API token may change. The handler limits it to the
// project it was issued for (A25), whichever assets that project holds.
func tokenScope(store.APIToken) store.Scope { return store.Everything }

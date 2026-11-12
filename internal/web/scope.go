package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// The scope of a request is the part of the inventory it may read or change
// (A67): every call to the store about assets, findings or digests passes it.
// SECURITY: this file is the only one of package web that grants
// store.Everything or the scope of an account; TestEverythingOnlyInScopeFile
// checks it.

// readScope is what the signed-in account may see: everything for an
// administrator or an account without restriction, the assets of its groups
// otherwise (A68); a request without a session sees nothing.
func readScope(r *http.Request) store.Scope {
	sess, ok := sessionFrom(r.Context())
	if !ok {
		return store.Scope{}
	}
	return sess.User.Scope()
}

// writeScope is what the signed-in account may change: the same as what it
// sees, as the role of each route already says who may write.
func writeScope(r *http.Request) store.Scope { return readScope(r) }

// requestScope is the scope of an object loaded by its id: what the account
// may see for a page, what it may change for a form.
func requestScope(r *http.Request) store.Scope {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return readScope(r)
	}
	return writeScope(r)
}

// listScope is the scope of a list filtered by group (?group=id): what the
// account sees of that group, nothing for a group it does not see. It returns
// the group chosen, 0 for none. q is the query of the list: that of the
// request, or the one a form or a vulnerability page names (next, back).
func listScope(r *http.Request, q url.Values) (store.Scope, int64) {
	sc := readScope(r)
	if g := groupParam(q); g != 0 {
		return sc.Only(g), g
	}
	return sc, 0
}

// groupParam reads the group filter of a list, 0 for none.
func groupParam(q url.Values) int64 {
	g, err := strconv.ParseInt(q.Get("group"), 10, 64)
	if err != nil || g < 0 {
		return 0
	}
	return g
}

// inScope binds a lookup of the inventory by id to the scope of the request
// (requestScope), for load.
func inScope[T any](r *http.Request, get func(context.Context, store.Scope, int64) (T, error)) func(context.Context, int64) (T, error) {
	return func(ctx context.Context, id int64) (T, error) { return get(ctx, requestScope(r), id) }
}

// tokenScope is what an API token may change. The handler limits it to the
// project it was issued for (A25), whichever assets that project holds: its
// components enter the groups that name the project.
func tokenScope(store.APIToken) store.Scope { return store.Everything }

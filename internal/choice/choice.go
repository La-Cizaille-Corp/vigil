// Package choice holds what the lists of options offered by forms and
// filters share: a stored value with its French label, and the questions
// asked of a list. It imports nothing of Vigil, so that every package can
// use it (inventory, tracking, cti, notify, digest, auth, web).
package choice

import "slices"

// Option is a value with a display label.
type Option struct {
	Value string
	Label string
}

// Label returns the label of value in opts, or value itself when it is not
// one of them. It does not tell whether value is known: Has does.
func Label(opts []Option, value string) string {
	if i := Rank(opts, value); i >= 0 {
		return opts[i].Label
	}
	return value
}

// Labels returns the labels of opts, in their order: what a form or a file
// accepts, named in the error that refuses another value.
func Labels(opts []Option) []string {
	out := make([]string, 0, len(opts))
	for _, o := range opts {
		out = append(out, o.Label)
	}
	return out
}

// Has reports whether value is one of opts.
func Has(opts []Option, value string) bool { return Rank(opts, value) >= 0 }

// Rank returns the position of value in opts, -1 when it is not one of them:
// statuses, criticalities or roles sort in the order of their list.
func Rank(opts []Option, value string) int {
	return slices.IndexFunc(opts, func(o Option) bool { return o.Value == value })
}

// KnownOnly keeps the values found in opts, each once, in the order given.
// SECURITY: each value of a filter adds a condition to a query, and SQLite
// refuses an expression deeper than 1000: without duplicates, a crafted URL or
// form cannot make a page fail. out only holds known values, so the Contains
// check stays cheap.
func KnownOnly(opts []Option, values []string) []string {
	var out []string
	for _, v := range values {
		if Has(opts, v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

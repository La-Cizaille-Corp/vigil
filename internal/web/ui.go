package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/fr"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// tagSelection is the data of the "tagFields" template.
type tagSelection struct {
	Countries, Sectors, Regulations []string
}

// accessChoice is the data of the "accessFields" template: the access of an
// account, neither choice made for a new one (A68: the form requires it),
// and the groups to check.
type accessChoice struct {
	All, Restricted bool
	Groups          []groupChoice
}

// groupChoice is a group offered in a form.
type groupChoice struct {
	ID      int64
	Name    string
	Checked bool
}

// accessForm is the form of the access of an existing account.
func accessForm(access store.Access, groups []store.Group) accessChoice {
	c := newAccessForm(groups)
	c.All, c.Restricted = access.All, !access.All
	for i := range c.Groups {
		c.Groups[i].Checked = slices.Contains(access.Groups, c.Groups[i].ID)
	}
	return c
}

// newAccessForm is the form of the access of a new account.
func newAccessForm(groups []store.Group) accessChoice {
	var c accessChoice
	for _, g := range groups {
		c.Groups = append(c.Groups, groupChoice{ID: g.ID, Name: g.Name})
	}
	return c
}

// syncTargets are the pages a synchronisation can be started from, and
// returned to afterwards.
var syncTargets = map[string]bool{"/": true, "/assets": true, "/findings": true}

// isoDate formats the date part of an ISO 8601 timestamp ("2024-02-09T09:15")
// as "09/02/2024"; other values are returned as they are.
func isoDate(v string) string {
	if len(v) < 10 {
		return v
	}
	t, err := time.Parse(time.DateOnly, v[:10])
	if err != nil {
		return v
	}
	return fr.Date(t)
}

// trackingSource names the source that checks an asset, "" when none does.
func trackingSource(a store.Asset) string {
	switch {
	case inventory.Queryable(a):
		return "OSV"
	case inventory.WholeVendor(a):
		return "NVD (éditeur)"
	case a.CPE != "":
		return "NVD"
	case inventory.ByName(a):
		return "NVD (nom)"
	}
	return ""
}

// splitTags splits a comma-separated list of tags.
func splitTags(v string) []string {
	var out []string
	for _, t := range strings.Split(v, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// findingTitle names a finding by its CVE when it has one: teams and news
// speak of CVE-2021-44228, not GHSA-jfh8-c2jp-5v3q. An advisory of several
// CVEs keeps its own name: the first of its 1 902 CVEs does not describe
// USN-8875-1 (A86).
func findingTitle(f store.Finding) string {
	if cve := findingCVE(f); cve != "" && cve != f.VulnID {
		return cve + " (" + f.VulnID + ")"
	}
	return f.VulnID
}

// findingCVE is the CVE of a finding, "" when it has none or several.
func findingCVE(f store.Finding) string {
	if cves := tracking.CVEs(f.VulnID, f.Aliases); len(cves) == 1 {
		return cves[0]
	}
	return ""
}

// maxAliases bounds the aliases named in a list row: an Ubuntu notice can
// have nearly two thousand.
const maxAliases = 3

// aliasList names the first aliases of a vulnerability, then how many more.
func aliasList(aliases []string) string {
	if len(aliases) <= maxAliases {
		return strings.Join(aliases, ", ")
	}
	more, word := len(aliases)-maxAliases, "autres"
	if more == 1 {
		word = "autre"
	}
	return strings.Join(aliases[:maxAliases], ", ") + " et " + strconv.Itoa(more) + " " + word
}

// syncView is the data of the "syncText" template: error details (source
// addresses, proxy messages) are for those who can act on them.
type syncView struct {
	tracking.Status
	Details    bool
	Restricted bool // Done is a percentage, out of a Total of 100
}

// syncFor is the state of the synchronisation as shown to u.
func (s *Server) syncFor(u *store.User) syncView { return newSyncView(s.syncStatus(), *u) }

// newSyncView shows st to u. SECURITY: a run goes through the whole
// inventory: an account restricted to groups (A68) sees whether it is going
// and how far, never the names of the assets nor the counts, which would
// tell of the other groups.
func newSyncView(st tracking.Status, u store.User) syncView {
	if !u.Restricted() {
		return syncView{Status: st, Details: auth.RoleAtLeast(u.Role, auth.RoleAnalyst)}
	}
	v := syncView{Restricted: true}
	v.Running, v.Started, v.Finished = st.Running, st.Started, st.Finished
	if st.Err != "" {
		v.Err = "failed" // shown as « échec », without details
	}
	if st.Total > 0 {
		v.Total, v.Done = 100, 100*st.Done/st.Total
	}
	return v
}

// syncPage follows a synchronisation: it reloads itself while it runs.
func (s *Server) syncPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "sync", page{Title: "Synchronisation", Refresh: s.syncStatus().Running})
}

// syncStatus is the state of the running or last synchronisation.
func (s *Server) syncStatus() tracking.Status {
	if s.Syncer == nil {
		return tracking.Status{}
	}
	return s.Syncer.Status()
}

// syncTimeout bounds a run started from the UI. Every request is bounded on
// its own: without an NVD key an asset takes about a minute, a kernel more.
const syncTimeout = 2 * time.Hour

// runSync matches the inventory against vulnerability sources in the
// background; it is a no-op when a sync is already running.
func (s *Server) runSync() {
	if s.Syncer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.background(), syncTimeout)
	defer cancel()
	if _, err := s.Syncer.Run(ctx); err != nil && !errors.Is(err, tracking.ErrRunning) {
		s.Log.Error("sync failed", "err", err)
	}
}

// runAssetSync checks one asset in the background. A sync in progress may
// have listed the inventory before the asset was added or changed, so the
// check waits for it instead of being dropped.
func (s *Server) runAssetSync(id int64) {
	if s.Syncer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.background(), syncTimeout)
	defer cancel()
	for {
		_, err := s.Syncer.RunAsset(ctx, id)
		if !errors.Is(err, tracking.ErrRunning) {
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.Log.Error("asset sync failed", "asset", id, "err", err)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// sentences formats error messages for display: Go errors are lowercase
// without final period, joined by newlines (errors.Join).
func sentences(msg string) string {
	lines := strings.Split(strings.TrimSpace(msg), "\n")
	for i, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		r, size := utf8.DecodeRuneInString(l)
		l = string(unicode.ToUpper(r)) + l[size:]
		if !strings.HasSuffix(l, ".") && !strings.HasSuffix(l, "?") && !strings.HasSuffix(l, "!") {
			l += "."
		}
		lines[i] = l
	}
	return strings.Join(lines, "\n")
}

// assetForm is an asset shown in its form, with the tags in use as hints under
// the tags field and, for an account restricted to groups, the tags and
// projects that keep an asset in them (A68).
type assetForm struct {
	store.Asset
	KnownTags                []store.TagCount
	GroupTags, GroupProjects []string
}

// newAssetForm prepares the form of a, with the tags the account may see as
// hints.
func (s *Server) newAssetForm(r *http.Request, a store.Asset) (assetForm, error) {
	f := assetForm{Asset: a}
	var err error
	if f.KnownTags, err = s.Store.ListAssetTags(r.Context(), readScope(r)); err != nil {
		return f, fmt.Errorf("asset tags: %w", err)
	}
	if sess, _ := sessionFrom(r.Context()); sess.User.Restricted() {
		groups, err := s.Store.ListGroups(r.Context(), readScope(r))
		if err != nil {
			return f, err
		}
		for _, g := range groups {
			f.GroupTags = append(f.GroupTags, g.Tags...)
			f.GroupProjects = append(f.GroupProjects, g.Projects...)
		}
		slices.Sort(f.GroupTags)
		slices.Sort(f.GroupProjects)
		f.GroupTags, f.GroupProjects = slices.Compact(f.GroupTags), slices.Compact(f.GroupProjects)
	}
	return f, nil
}

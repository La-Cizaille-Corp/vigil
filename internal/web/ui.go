package web

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
	"github.com/La-Cizaille-Corp/vigil/internal/tracking"
)

// roles are the user roles, labelled in French.
var roles = []inventory.Option{
	{Value: "admin", Label: "administrateur"},
	{Value: "analyst", Label: "analyste"},
	{Value: "viewer", Label: "lecteur"},
}

// tagSelection is the data of the "tagFields" template.
type tagSelection struct {
	Countries, Sectors, Regulations []string
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
	t, err := time.Parse("2006-01-02", v[:10])
	if err != nil {
		return v
	}
	return t.Format("02/01/2006")
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

// syncStatus is the state of the running or last synchronisation.
func (s *Server) syncStatus() tracking.Status {
	if s.Syncer == nil {
		return tracking.Status{}
	}
	return s.Syncer.Status()
}

// runSync matches the inventory against vulnerability sources in the
// background; it is a no-op when a sync is already running.
func (s *Server) runSync() {
	if s.Syncer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.background(), 15*time.Minute)
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
	ctx, cancel := context.WithTimeout(s.background(), 15*time.Minute)
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

// formatDays formats a duration in days: "< 1 j", "3,5 j", "12 j".
func formatDays(d float64) string {
	switch {
	case d < 1:
		return "< 1 j"
	case d < 10:
		return strings.Replace(strconv.FormatFloat(d, 'f', 1, 64), ".", ",", 1) + " j"
	}
	return strconv.FormatFloat(d, 'f', 0, 64) + " j"
}

// knownTags lists the asset tags in use, as hints under the tags field.
func (s *Server) knownTags() []store.TagCount {
	ctx, cancel := context.WithTimeout(s.background(), 5*time.Second)
	defer cancel()
	tags, err := s.Store.AssetTags(ctx)
	if err != nil {
		s.Log.Warn("asset tags", "err", err)
	}
	return tags
}

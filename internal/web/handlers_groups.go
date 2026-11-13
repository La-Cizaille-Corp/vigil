package web

import (
	"errors"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/fr"
	"github.com/La-Cizaille-Corp/vigil/internal/inventory"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// --- asset groups (administrators, A68) -------------------------------------

// maxGroupRules bounds the tags and projects of a group: each one is compared
// with every asset, in every query of a restricted account.
const maxGroupRules = 100

// groupPath is the page of a group.
func groupPath(id int64) string { return "/settings/groups/" + strconv.FormatInt(id, 10) }

func (s *Server) groupList(w http.ResponseWriter, r *http.Request) {
	s.renderGroups(w, r, http.StatusOK, "")
}

// renderGroups shows the groups, what they cover, and the assets in none.
func (s *Server) renderGroups(w http.ResponseWriter, r *http.Request, status int, formErr string) {
	groups, err := s.Store.ListGroups(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	ungrouped, err := s.Store.UngroupedAssets(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "groups", page{Title: "Groupes d'actifs", Error: formErr,
		Data: map[string]any{"Groups": groups, "Ungrouped": ungrouped}})
}

// groupName reads the name of a group: 1 to clip.MaxName characters, without a
// comma, so that vigil user -groups can list several.
func groupName(r *http.Request) (string, bool) {
	name := strings.Join(strings.Fields(r.PostFormValue("name")), " ")
	return name, name != "" && clip.Fits(name, clip.MaxName) && !strings.Contains(name, ",")
}

const (
	errGroupName   = "Indiquez un nom de groupe de 100 caractères au plus, sans virgule."
	errGroupExists = "Un groupe porte déjà ce nom (majuscules et minuscules ne comptent pas)."
)

func (s *Server) groupCreate(w http.ResponseWriter, r *http.Request) {
	name, ok := groupName(r)
	if !ok {
		s.renderGroups(w, r, http.StatusBadRequest, errGroupName)
		return
	}
	id, err := s.Store.CreateGroup(r.Context(), name)
	if errors.Is(err, store.ErrExists) {
		s.renderGroups(w, r, http.StatusBadRequest, errGroupExists)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "group_create", "id", id, "name", name)
	redirect(w, r, groupPath(id), "group-created")
}

func (s *Server) groupShow(w http.ResponseWriter, r *http.Request) {
	s.renderGroup(w, r, http.StatusOK, "")
}

// ruleChoice is a tag or a project offered as a rule of a group, with the
// number of active assets bearing it.
type ruleChoice struct {
	Value   string
	N       int
	Checked bool
}

// ruleChoices lists the values in use and those of the rules, in order, the
// rules checked: a rule whose value no asset bears yet stays shown.
func ruleChoices(inUse map[string]int, rules []string) []ruleChoice {
	values := slices.Collect(maps.Keys(inUse))
	for _, v := range rules {
		if _, ok := inUse[v]; !ok {
			values = append(values, v)
		}
	}
	slices.SortFunc(values, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	out := make([]ruleChoice, 0, len(values))
	for _, v := range values {
		out = append(out, ruleChoice{Value: v, N: inUse[v], Checked: slices.Contains(rules, v)})
	}
	return out
}

// renderGroup shows a group: its rules among the tags and projects in use,
// what it covers, and the forms to rename or delete it.
func (s *Server) renderGroup(w http.ResponseWriter, r *http.Request, status int, formErr string) {
	g, ok := load(s, w, r, inScope(r, s.Store.Group))
	if !ok {
		return
	}
	tags, err := s.Store.ListAssetTags(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	assets, err := s.Store.ListAssets(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	tagCounts, projectCounts := map[string]int{}, map[string]int{}
	for _, t := range tags {
		tagCounts[t.Tag] = t.N
	}
	for _, a := range assets {
		if a.Project != "" {
			projectCounts[a.Project]++
		}
	}
	s.render(w, r, status, "group", page{Title: "Groupe « " + g.Name + " »", Error: formErr, Data: map[string]any{
		"Group": g, "Tags": ruleChoices(tagCounts, g.Tags), "Projects": ruleChoices(projectCounts, g.Projects)}})
}

// groupRename renames a group.
func (s *Server) groupRename(w http.ResponseWriter, r *http.Request) {
	name, ok := groupName(r)
	if !ok {
		s.renderGroup(w, r, http.StatusBadRequest, errGroupName)
		return
	}
	s.change(w, r, change{action: "group_rename", detail: []any{"name", name}, msg: "group-renamed",
		apply: func(id int64) error { return s.Store.RenameGroup(r.Context(), id, name) },
		to:    r.URL.Path,
		refuse: func(err error) bool {
			if !errors.Is(err, store.ErrExists) {
				return false
			}
			s.renderGroup(w, r, http.StatusBadRequest, errGroupExists)
			return true
		}})
}

// groupRules replaces the rules of a group: the tags and projects checked,
// and those typed for values no asset bears yet.
func (s *Server) groupRules(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Formulaire invalide.", http.StatusBadRequest)
		return
	}
	tags := inventory.NormalizeTags(append(r.PostForm["tag"], inventory.ParseTags(r.PostFormValue("new_tag"))...))
	var projects []string
	for _, p := range append(r.PostForm["project"], r.PostFormValue("new_project")) {
		if p = strings.TrimSpace(p); p != "" && !slices.Contains(projects, p) {
			projects = append(projects, p)
		}
	}
	valid := len(tags)+len(projects) <= maxGroupRules
	for _, t := range tags {
		valid = valid && clip.Fits(t, inventory.MaxTagLen) && !strings.ContainsAny(t, ",;\x00")
	}
	for _, p := range projects {
		valid = valid && clip.Fits(p, inventory.MaxProjectLen)
	}
	if !valid {
		s.renderGroup(w, r, http.StatusBadRequest, "Règles refusées : 100 au plus, étiquettes de 40 caractères et projets de 200 au plus.")
		return
	}
	s.change(w, r, change{action: "group_rules", msg: "group-rules-saved", to: strings.TrimSuffix(r.URL.Path, "/rules"),
		detail: []any{"tags", strings.Join(tags, ","), "projects", strings.Join(projects, ",")},
		apply:  func(id int64) error { return s.Store.SetGroupRules(r.Context(), id, tags, projects) }})
}

// groupDelete removes a group and its digests; its assets stay in the
// inventory. A group with channels is kept (D7).
func (s *Server) groupDelete(w http.ResponseWriter, r *http.Request) {
	g, ok := load(s, w, r, inScope(r, s.Store.Group))
	if !ok {
		return
	}
	err := s.Store.DeleteGroup(r.Context(), g.ID)
	if errors.Is(err, store.ErrGroupInUse) {
		s.renderGroup(w, r, http.StatusConflict, "Des canaux de notification sont limités à ce groupe : rattachez-les à "+
			"tout l'inventaire ou à un autre groupe, ou supprimez-les (Paramètres → Notifications), avant de le supprimer.")
		return
	}
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	s.audit(r, "group_delete", "id", g.ID, "name", g.Name)
	redirect(w, r, "/settings/groups", "group-deleted")
}

// ruleValues names tags and projects in a sentence: « l'étiquette « web »,
// le projet « boutique » ou l'étiquette « prod » », joined by conj (fr.Join).
func ruleValues(tags, projects []string, conj string) string {
	var parts []string
	for _, t := range tags {
		parts = append(parts, "l'étiquette « "+t+" »")
	}
	for _, p := range projects {
		parts = append(parts, "le projet « "+p+" »")
	}
	return fr.Join(parts, conj)
}

// outsideGroups explains a write refused because it would move an asset
// across groups the account does not hold (A68): which of its tags and
// projects tie it to the groups of others, or which ones would keep it in
// the account's. refused is false for any other error.
func outsideGroups(err error) (msg string, refused bool) {
	var e *store.OutsideGroupsError
	if !errors.As(err, &e) {
		return "", false
	}
	foreign := ruleValues(e.ForeignTags, e.ForeignProjects, "et")
	switch {
	case e.Deleting:
		return "« " + e.Asset + " » fait aussi partie d'un groupe dont vous ne faites pas partie (" + foreign +
			") : seul un compte qui voit tout l'inventaire peut le supprimer.", true
	case foreign != "":
		return "« " + e.Asset + " » : " + foreign + " le rattache à un groupe dont vous ne faites pas partie ; " +
			"vous ne pouvez ni l'ajouter ni le retirer.", true
	case len(e.Tags)+len(e.Projects) > 0:
		return "« " + e.Asset + " » doit rester dans un de vos groupes : donnez-lui " +
			ruleValues(e.Tags, e.Projects, "ou") + ".", true
	}
	return "« " + e.Asset + " » ne serait dans aucun groupe, et votre compte n'en a aucun : demandez à un administrateur.", true
}

// accessFromForm reads the access chosen for an account (A68): everything,
// or the groups checked. chosen is false when the form says neither: the
// choice is required, and the database refuses by default.
func accessFromForm(r *http.Request) (access store.Access, chosen bool) {
	if err := r.ParseForm(); err != nil {
		return access, false
	}
	switch r.PostFormValue("access") {
	case "all":
		return store.Access{All: true}, true
	case "groups":
		for _, raw := range r.PostForm["group"] {
			if id, err := strconv.ParseInt(raw, 10, 64); err == nil && !slices.Contains(access.Groups, id) {
				access.Groups = append(access.Groups, id)
			}
		}
		return access, true
	}
	return access, false
}

// accessDetail is the audit detail of an access (store.AuditAccess).
func (s *Server) accessDetail(r *http.Request, access store.Access) ([]any, error) {
	groups, err := s.Store.ListGroups(r.Context(), readScope(r))
	if err != nil {
		return nil, err
	}
	return store.AuditAccess(access, groups), nil
}

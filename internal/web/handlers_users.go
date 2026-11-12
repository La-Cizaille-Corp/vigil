package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/clip"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// newPassword is a temporary password shown once to the administrator.
type newPassword struct {
	Username, Password string
}

func (s *Server) userList(w http.ResponseWriter, r *http.Request) {
	secret, _ := s.takeOnce(r, oncePassword).(*newPassword)
	s.renderUsers(w, r, http.StatusOK, "", secret)
}

// newToken is the API token just created by this session, shown once.
func (s *Server) newToken(r *http.Request) string {
	v, _ := s.takeOnce(r, onceToken).(string)
	return v
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, status int, formErr string, secret *newPassword) {
	accounts, err := s.Store.ListUsers(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	policy, err := s.Store.TOTPPolicy(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groups, err := s.Store.ListGroups(r.Context(), readScope(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	names := make(map[int64]string, len(groups))
	for _, g := range groups {
		names[g.ID] = g.Name
	}
	s.render(w, r, status, "users", page{Title: "Utilisateurs", Error: formErr,
		Data: map[string]any{"Users": accounts, "Secret": secret, "Policy": policy, "Groups": groups, "GroupNames": names}})
}

// userTOTPPolicy sets who must use a second factor.
func (s *Server) userTOTPPolicy(w http.ResponseWriter, r *http.Request) {
	policy := r.PostFormValue("policy")
	if err := s.Store.SetTOTPPolicy(r.Context(), policy); err != nil {
		s.renderUsers(w, r, http.StatusBadRequest, "Choix inconnu.", nil)
		return
	}
	s.audit(r, "totp_policy", "required", policy)
	redirect(w, r, "/settings/users", "totp-policy-saved")
}

// userCreate adds an account with a generated temporary password and the
// access chosen in the form (A68).
func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	username, role := strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("role")
	if username == "" || !clip.Fits(username, auth.MaxUsernameLength) || !auth.ValidRole(role) {
		s.renderUsers(w, r, http.StatusBadRequest, "Indiquez un nom (64 caractères maximum) et un rôle.", nil)
		return
	}
	access, chosen := accessFromForm(r)
	if !chosen {
		s.renderUsers(w, r, http.StatusBadRequest, errNoAccess, nil)
		return
	}
	detail, err := s.accessDetail(r, access)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	password, hash, err := temporaryPassword()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	id, err := s.Store.CreateUser(r.Context(), username, hash, role, access)
	if errors.Is(err, store.ErrExists) {
		s.renderUsers(w, r, http.StatusBadRequest, "Ce nom d'utilisateur existe déjà (majuscules et minuscules ne comptent pas).", nil)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "user_create", append([]any{"id", id, "user", username, "role", role}, detail...)...)
	// SECURITY: the password is displayed once, on the page this redirects to.
	s.keepOnce(r, oncePassword, &newPassword{Username: username, Password: password})
	redirect(w, r, "/settings/users", "user-created")
}

// userRole changes the role of another account.
func (s *Server) userRole(w http.ResponseWriter, r *http.Request) {
	role := r.PostFormValue("role")
	if !auth.ValidRole(role) {
		s.renderUsers(w, r, http.StatusBadRequest, "Rôle inconnu.", nil)
		return
	}
	s.userChange(w, r, change{action: "user_role", detail: []any{"role", role}, msg: "user-updated",
		apply: func(id int64) error { return s.Store.SetRole(r.Context(), id, role) }})
}

// errNoAccess asks for the access of an account: the form requires it.
const errNoAccess = "Choisissez l'accès du compte : tout l'inventaire, ou seulement certains groupes."

// userAccess changes what another account sees: everything, or its groups.
func (s *Server) userAccess(w http.ResponseWriter, r *http.Request) {
	access, chosen := accessFromForm(r)
	if !chosen {
		s.renderUsers(w, r, http.StatusBadRequest, errNoAccess, nil)
		return
	}
	detail, err := s.accessDetail(r, access)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.userChange(w, r, change{action: "user_access", detail: detail, msg: "access-updated",
		apply: func(id int64) error { return s.Store.SetUserAccess(r.Context(), id, access) }})
}

func (s *Server) userDisable(w http.ResponseWriter, r *http.Request) {
	s.userChange(w, r, change{action: "user_disable", msg: "user-disabled",
		apply: func(id int64) error { return s.Store.SetDisabled(r.Context(), id, true) }})
}

func (s *Server) userEnable(w http.ResponseWriter, r *http.Request) {
	s.userChange(w, r, change{action: "user_enable", msg: "user-enabled",
		apply: func(id int64) error { return s.Store.SetDisabled(r.Context(), id, false) }})
}

// userTOTPReset removes the second factor of a user who lost it, and ends
// that user's sessions.
func (s *Server) userTOTPReset(w http.ResponseWriter, r *http.Request) {
	s.userChange(w, r, change{action: "totp_reset", msg: "user-totp-reset",
		apply: func(id int64) error { return s.Store.ResetTOTP(r.Context(), id) }})
}

// userPassword replaces the password of another account with a generated
// temporary one and ends its sessions.
func (s *Server) userPassword(w http.ResponseWriter, r *http.Request) {
	s.userChange(w, r, change{action: "password_reset", msg: "password-reset", apply: func(id int64) error {
		a, err := s.Store.User(r.Context(), id)
		if err != nil {
			return err
		}
		if a.Disabled {
			return store.ErrNotFound
		}
		password, hash, err := temporaryPassword()
		if err != nil {
			return err
		}
		if err := s.Store.ResetPassword(r.Context(), id, hash); err != nil {
			return err
		}
		// SECURITY: the password is displayed once, on the page this redirects to.
		s.keepOnce(r, oncePassword, &newPassword{Username: a.Username, Password: password})
		return nil
	}})
}

// errOwnAccount refuses a change of the administrator's own account from the
// list of users: it is made in « Mon compte » (no self-lockout).
var errOwnAccount = errors.New("own account")

// userChange applies c to the account named in the path, never the
// administrator's own, then goes back to the list of users; a refusal (own
// account, last active administrator) is shown on the list.
func (s *Server) userChange(w http.ResponseWriter, r *http.Request, c change) {
	sess, _ := sessionFrom(r.Context())
	apply := c.apply
	c.apply = func(id int64) error {
		if id == sess.User.ID {
			return errOwnAccount
		}
		return apply(id)
	}
	c.to = "/settings/users"
	c.refuse = func(err error) bool {
		switch {
		case errors.Is(err, errOwnAccount):
			s.renderUsers(w, r, http.StatusBadRequest, "Modifiez votre propre compte dans « Mon compte ».", nil)
		case errors.Is(err, store.ErrLastAdmin):
			s.renderUsers(w, r, http.StatusConflict, "Il doit rester au moins un administrateur actif.", nil)
		default:
			return false
		}
		return true
	}
	s.change(w, r, c)
}

// temporaryPassword returns a random password and its hash.
func temporaryPassword() (password, hash string, err error) {
	if password, err = auth.NewPassword(); err != nil {
		return "", "", err
	}
	hash, err = auth.HashPassword(password)
	return password, hash, err
}

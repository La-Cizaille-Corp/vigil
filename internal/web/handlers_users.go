package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
	"github.com/La-Cizaille-Corp/vigil/internal/store"
)

// newPassword is a temporary password shown once to the administrator.
type newPassword struct {
	Username, Password string
}

func (s *Server) userList(w http.ResponseWriter, r *http.Request) {
	s.renderUsers(w, r, http.StatusOK, "", nil)
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, status int, formErr string, secret *newPassword) {
	accounts, err := s.Store.ListAccounts(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "users", page{Title: "Utilisateurs", Error: formErr,
		Data: map[string]any{"Users": accounts, "Secret": secret}})
}

// userCreate adds an account with a generated temporary password.
func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	username, role := strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("role")
	if username == "" || len(username) > 64 || !auth.ValidRole(role) {
		s.renderUsers(w, r, http.StatusBadRequest, "Indiquez un nom (64 caractères maximum) et un rôle.", nil)
		return
	}
	if _, err := s.Store.AccountByName(r.Context(), username); err == nil {
		s.renderUsers(w, r, http.StatusBadRequest, "Ce nom d'utilisateur existe déjà.", nil)
		return
	}
	password, hash, err := temporaryPassword()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	id, err := s.Store.CreateUser(r.Context(), username, hash, role)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sess, _ := sessionFrom(r.Context())
	s.audit(r, sess.User.ID, "user_create", "id="+strconv.FormatInt(id, 10)+" "+username+" role="+role)
	// SECURITY: the password is displayed once, in this response only.
	s.renderUsers(w, r, http.StatusOK, "", &newPassword{Username: username, Password: password})
}

// userRole changes the role of another account.
func (s *Server) userRole(w http.ResponseWriter, r *http.Request) {
	role := r.PostFormValue("role")
	if !auth.ValidRole(role) {
		s.renderUsers(w, r, http.StatusBadRequest, "Rôle inconnu.", nil)
		return
	}
	s.userAction(w, r, "user_role", "role="+role, "user-updated", func(id int64) error {
		return s.Store.SetRole(r.Context(), id, role)
	})
}

func (s *Server) userDisable(w http.ResponseWriter, r *http.Request) {
	s.userAction(w, r, "user_disable", "", "user-disabled", func(id int64) error {
		return s.Store.SetDisabled(r.Context(), id, true)
	})
}

func (s *Server) userEnable(w http.ResponseWriter, r *http.Request) {
	s.userAction(w, r, "user_enable", "", "user-enabled", func(id int64) error {
		return s.Store.SetDisabled(r.Context(), id, false)
	})
}

// userTOTPReset removes the second factor of a user who lost it, and ends
// that user's sessions.
func (s *Server) userTOTPReset(w http.ResponseWriter, r *http.Request) {
	s.userAction(w, r, "totp_reset", "", "user-totp-reset", func(id int64) error {
		return s.Store.ResetTOTP(r.Context(), id)
	})
}

// userPassword replaces the password of another account with a generated
// temporary one and ends its sessions.
func (s *Server) userPassword(w http.ResponseWriter, r *http.Request) {
	var target store.Account
	var password string
	ok := s.userAction(w, r, "password_reset", "", "", func(id int64) error {
		a, err := s.Store.AccountByID(r.Context(), id)
		if err != nil {
			return err
		}
		if a.Disabled {
			return store.ErrNotFound
		}
		pw, hash, err := temporaryPassword()
		if err != nil {
			return err
		}
		target, password = a, pw
		return s.Store.ResetPassword(r.Context(), id, hash)
	})
	if ok {
		s.renderUsers(w, r, http.StatusOK, "", &newPassword{Username: target.Username, Password: password})
	}
}

// userAction applies a change to the account named in the path, never the
// administrator's own (no self-lockout), audits it, then redirects to the
// list with msg; with msg "" it leaves the response to the caller.
func (s *Server) userAction(w http.ResponseWriter, r *http.Request, action, detail, msg string, change func(int64) error) bool {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.notFound(w)
		return false
	}
	sess, _ := sessionFrom(r.Context())
	if id == sess.User.ID {
		s.renderUsers(w, r, http.StatusBadRequest, "Modifiez votre propre compte dans « Mon compte ».", nil)
		return false
	}
	switch err := change(id); {
	case errors.Is(err, store.ErrLastAdmin):
		s.renderUsers(w, r, http.StatusConflict, "Il doit rester au moins un administrateur actif.", nil)
		return false
	case errors.Is(err, store.ErrNotFound):
		s.notFound(w)
		return false
	case err != nil:
		s.serverError(w, r, err)
		return false
	}
	s.audit(r, sess.User.ID, action, strings.TrimSpace("id="+strconv.FormatInt(id, 10)+" "+detail))
	if msg != "" {
		redirect(w, r, "/settings/users", msg)
	}
	return true
}

// temporaryPassword returns a random password and its hash.
func temporaryPassword() (password, hash string, err error) {
	if password, err = auth.NewPassword(); err != nil {
		return "", "", err
	}
	hash, err = auth.HashPassword(password)
	return password, hash, err
}

package web

import (
	"fmt"
	"net/http"
	"time"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
)

// checkTOTP verifies the second factor of a user whose password is valid.
// Users without TOTP pass.
func (s *Server) checkTOTP(r *http.Request, userID int64, code string) (bool, error) {
	secret, _, last, err := s.Store.UserTOTP(r.Context(), userID)
	if err != nil || secret == "" {
		return err == nil, err
	}
	step, ok := auth.VerifyTOTP(secret, code, time.Now(), last)
	if !ok {
		return false, nil
	}
	// SECURITY: the step is consumed atomically, so two parallel requests
	// cannot both use the same code.
	return s.Store.UseTOTPStep(r.Context(), userID, step)
}

// totpAttempt applies the login limiter to second-factor checks made from an
// existing session, keyed by user: a stolen session cannot brute-force codes.
func (s *Server) totpAttempt(w http.ResponseWriter, r *http.Request, userID int64) (string, bool) {
	key := fmt.Sprintf("totp:%d", userID)
	if !s.limiter.Allowed(key) {
		s.renderAccount(w, r, http.StatusTooManyRequests, "Trop de codes invalides. Réessayez dans quelques minutes.")
		return key, false
	}
	return key, true
}

// endOtherSessions logs out the user's other browsers after a security change.
func (s *Server) endOtherSessions(r *http.Request, userID int64) error {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return err
	}
	return s.Store.DeleteOtherSessions(r.Context(), userID, auth.HashToken(cookie.Value))
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	s.renderAccount(w, r, http.StatusOK, "")
}

func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, status int, formErr string) {
	sess, _ := sessionFrom(r.Context())
	secret, pending, _, err := s.Store.UserTOTP(r.Context(), sess.User.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	data := map[string]any{"Enabled": secret != "", "Pending": pending}
	if pending != "" {
		data["URI"] = auth.TOTPURI("Vigil", sess.User.Username, pending)
	}
	s.render(w, r, status, "account", page{Title: "Mon compte", Error: formErr, Data: data})
}

func (s *Server) totpStart(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	secret, err := auth.NewTOTPSecret()
	if err == nil {
		err = s.Store.SetTOTPPending(r.Context(), sess.User.ID, secret)
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	redirect(w, r, "/account", "")
}

func (s *Server) totpConfirm(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	key, ok := s.totpAttempt(w, r, sess.User.ID)
	if !ok {
		return
	}
	_, pending, _, err := s.Store.UserTOTP(r.Context(), sess.User.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	step, ok := auth.VerifyTOTP(pending, r.PostFormValue("code"), time.Now(), 0)
	if pending == "" || !ok {
		s.limiter.Fail(key)
		s.renderAccount(w, r, http.StatusBadRequest, "Code invalide : vérifiez l'heure de votre téléphone et réessayez.")
		return
	}
	if err := s.Store.EnableTOTP(r.Context(), sess.User.ID, step); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.limiter.Reset(key)
	if err := s.endOtherSessions(r, sess.User.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, sess.User.ID, "totp_enable", "")
	redirect(w, r, "/account", "totp-enabled")
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	key, allowed := s.totpAttempt(w, r, sess.User.ID)
	if !allowed {
		return
	}
	// SECURITY: a stolen session alone cannot remove the second factor.
	ok, err := s.checkTOTP(r, sess.User.ID, r.PostFormValue("code"))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.limiter.Fail(key)
		s.renderAccount(w, r, http.StatusBadRequest, "Code invalide.")
		return
	}
	if err := s.Store.DisableTOTP(r.Context(), sess.User.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.limiter.Reset(key)
	if err := s.endOtherSessions(r, sess.User.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, sess.User.ID, "totp_disable", "")
	redirect(w, r, "/account", "totp-disabled")
}

// passwordChange replaces the password of the signed-in user, who must give
// the current one, and closes the user's other sessions.
func (s *Server) passwordChange(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	key := fmt.Sprintf("password:%d", sess.User.ID)
	if !s.limiter.Allowed(key) {
		s.renderAccount(w, r, http.StatusTooManyRequests, "Trop de tentatives. Réessayez dans quelques minutes.")
		return
	}
	current, next := r.PostFormValue("current"), r.PostFormValue("new")
	if len(current) > maxPasswordBytes || len(next) > maxPasswordBytes {
		s.renderAccount(w, r, http.StatusBadRequest, "Mot de passe trop long.")
		return
	}
	user, err := s.Store.UserByName(r.Context(), sess.User.Username)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if ok, err := auth.VerifyPassword(current, user.PasswordHash); err != nil || !ok {
		s.limiter.Fail(key)
		s.renderAccount(w, r, http.StatusBadRequest, "Mot de passe actuel incorrect.")
		return
	}
	if next != r.PostFormValue("confirm") {
		s.renderAccount(w, r, http.StatusBadRequest, "Les deux nouveaux mots de passe ne correspondent pas.")
		return
	}
	hash, err := auth.HashPassword(next)
	if err != nil {
		s.renderAccount(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Store.SetPassword(r.Context(), user.ID, hash); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.limiter.Reset(key)
	if err := s.endOtherSessions(r, user.ID); err != nil {
		s.Log.Warn("end other sessions", "err", err)
	}
	s.audit(r, user.ID, "password_change", "")
	redirect(w, r, "/account", "password-changed")
}

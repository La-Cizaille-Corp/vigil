package web

import (
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
	return true, s.Store.UseTOTPStep(r.Context(), userID, step)
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
	_, pending, _, err := s.Store.UserTOTP(r.Context(), sess.User.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	step, ok := auth.VerifyTOTP(pending, r.PostFormValue("code"), time.Now(), 0)
	if pending == "" || !ok {
		s.renderAccount(w, r, http.StatusBadRequest, "Code invalide : vérifiez l'heure de votre téléphone et réessayez.")
		return
	}
	if err := s.Store.EnableTOTP(r.Context(), sess.User.ID, step); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, sess.User.ID, "totp_enable", "")
	redirect(w, r, "/account", "totp-enabled")
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	// SECURITY: a stolen session alone cannot remove the second factor.
	ok, err := s.checkTOTP(r, sess.User.ID, r.PostFormValue("code"))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.renderAccount(w, r, http.StatusBadRequest, "Code invalide.")
		return
	}
	if err := s.Store.DisableTOTP(r.Context(), sess.User.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, sess.User.ID, "totp_disable", "")
	redirect(w, r, "/account", "totp-disabled")
}

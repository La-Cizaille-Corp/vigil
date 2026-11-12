package main

import (
	"strings"
	"testing"

	"github.com/La-Cizaille-Corp/vigil/internal/auth"
)

// The help of the command line says the whole password rule, the common
// passwords as well as the length, for the commands that choose one.
func TestUsageNamesThePasswordRule(t *testing.T) {
	if !strings.Contains(usage, "Mot de passe de user add et user reset-password : "+auth.PasswordHelp+".") {
		t.Errorf("usage does not name the password rule %q:\n%s", auth.PasswordHelp, usage)
	}
}

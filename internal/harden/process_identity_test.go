package harden

import (
	"testing"

	"github.com/KLORQ/quarshell-policy/corepolicy"
)

func TestProcessIdentityFailureIsNeverBestEffort(t *testing.T) {
	_, err := Apply(t.Context(), Options{
		Doc:  policy.Document{Process: &policy.Process{RunAsUser: "quarshell-user-that-does-not-exist"}},
		Mode: ModeBestEffort,
	})
	if err == nil {
		t.Fatal("invalid process identity was ignored in best-effort mode")
	}
}

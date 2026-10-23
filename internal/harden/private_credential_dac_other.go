//go:build !linux

package harden

import (
	"os"

	"github.com/KLORQ/quarshell-policy/corepolicy"
)

func privateCredentialDirOwnedByCurrentUser(os.FileInfo) bool { return true }

func privateCredentialDACIsolationAvailable(policy.Document, bool) bool { return false }

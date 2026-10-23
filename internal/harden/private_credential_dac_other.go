//go:build !linux

package harden

import (
	"os"

	"github.com/KLORQ/quarshell-core/policy"
)

func privateCredentialDirOwnedByCurrentUser(os.FileInfo) bool { return true }

func privateCredentialDACIsolationAvailable(policy.Document, bool) bool { return false }

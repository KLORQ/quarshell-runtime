//go:build linux

package harden

import (
	"os"
	"syscall"

	"github.com/KLORQ/quarshell-core/policy"
)

func privateCredentialDirOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func privateCredentialDACIsolationAvailable(doc policy.Document, noDrop bool) bool {
	if noDrop {
		return false
	}
	uid, _, _, err := targetIDs(doc)
	return err == nil && uid != os.Geteuid()
}

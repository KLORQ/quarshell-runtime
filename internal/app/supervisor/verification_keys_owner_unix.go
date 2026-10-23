//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package supervisor

import (
	"os"
	"syscall"
)

func ownedByEffectiveIdentity(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Gid == uint32(os.Getegid())
}

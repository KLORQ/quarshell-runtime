//go:build darwin || freebsd || openbsd || netbsd || dragonfly

package supervisor

import "testing"

func enableTestSubreaper(*testing.T) {}

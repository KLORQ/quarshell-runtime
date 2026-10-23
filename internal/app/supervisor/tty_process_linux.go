//go:build linux

package supervisor

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// mainProcessSysProcAttr keeps the canonical process in its own process group
// and, when the supervisor inherited a PTY, gives that group the terminal's
// foreground ownership. That lets the process read stdin, use shell job
// control, and receive terminal-generated signals while the supervisor retains
// stable process-group lifecycle control.
func mainProcessSysProcAttr(stdin *os.File) *syscall.SysProcAttr {
	attributes := &syscall.SysProcAttr{Setpgid: true}
	if stdin == nil {
		return attributes
	}
	if _, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS); err == nil {
		attributes.Foreground = true
		attributes.Ctty = 0
	}
	return attributes
}

//go:build !linux

package supervisor

import (
	"os"
	"syscall"
)

func mainProcessSysProcAttr(*os.File) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

//go:build windows

package supervisor

import (
	"os"
	"syscall"
)

func mainProcessSysProcAttr(*os.File) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}

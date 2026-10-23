//go:build !linux

package sshserver

import (
	"errors"

	"golang.org/x/crypto/ssh"
)

type process struct{}

func startProcess(argv, env []string, dir string, pty *ptyRequest, ch ssh.Channel) (*process, error) {
	return nil, errors.New("sshserver: sandbox sessions are only supported on linux")
}

func (p *process) wait() int                { return 255 }
func (p *process) resize(rows, cols uint32) {}
func (p *process) signal(name string)       {}
func (p *process) hangup()                  {}

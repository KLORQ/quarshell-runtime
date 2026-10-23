//go:build linux

package sshserver

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

type process struct {
	cmd      *exec.Cmd
	master   *os.File
	copies   sync.WaitGroup
	exited   atomic.Bool
	waitOnce sync.Once
	waitDone chan struct{}
	exitCode int
}

func openPTY() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	fd := int(m.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("unlockpt: %w", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("ptsname: %w", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		_ = m.Close()
		return nil, nil, err
	}
	return m, s, nil
}

func setWinsize(f *os.File, rows, cols uint32) {
	if f == nil || rows == 0 || cols == 0 {
		return
	}
	_ = unix.IoctlSetWinsize(int(f.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: uint16(rows), Col: uint16(cols)})
}

func startProcess(argv, env []string, dir string, pty *ptyRequest, ch ssh.Channel) (*process, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty argv")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	if dir != "" {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			cmd.Dir = dir
		}
	}
	p := &process{cmd: cmd, waitDone: make(chan struct{})}
	if pty != nil {
		master, slave, err := openPTY()
		if err != nil {
			return nil, err
		}
		setWinsize(master, pty.Rows, pty.Cols)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		if err := cmd.Start(); err != nil {
			_ = master.Close()
			_ = slave.Close()
			return nil, err
		}
		_ = slave.Close()
		p.master = master
		go func() { _, _ = io.Copy(master, ch) }()
		p.copies.Add(1)
		go func() {
			defer p.copies.Done()
			// Reading the master returns EIO once every slave fd is closed.
			_, _ = io.Copy(ch, master)
		}()
		return p, nil
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		_, _ = io.Copy(stdin, ch)
		_ = stdin.Close()
	}()
	p.copies.Add(2)
	go func() { defer p.copies.Done(); _, _ = io.Copy(ch, stdout) }()
	go func() { defer p.copies.Done(); _, _ = io.Copy(ch.Stderr(), stderr) }()
	return p, nil
}

// wait drains output, reaps the child and returns its exit code.
func (p *process) wait() int {
	if p == nil || p.cmd == nil {
		return 255
	}
	p.waitOnce.Do(func() {
		p.copies.Wait()
		err := p.cmd.Wait()
		if err == nil {
			p.exitCode = 0
		} else {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
					p.exitCode = 128 + int(ws.Signal())
				} else {
					p.exitCode = ee.ExitCode()
				}
			} else {
				p.exitCode = 255
			}
		}
		p.exited.Store(true)
		if p.master != nil {
			_ = p.master.Close()
		}
		close(p.waitDone)
	})
	<-p.waitDone
	return p.exitCode
}

func (p *process) resize(rows, cols uint32) { setWinsize(p.master, rows, cols) }

var sshSignals = map[string]syscall.Signal{
	"ABRT": syscall.SIGABRT, "ALRM": syscall.SIGALRM, "FPE": syscall.SIGFPE,
	"HUP": syscall.SIGHUP, "ILL": syscall.SIGILL, "INT": syscall.SIGINT,
	"KILL": syscall.SIGKILL, "PIPE": syscall.SIGPIPE, "QUIT": syscall.SIGQUIT,
	"SEGV": syscall.SIGSEGV, "TERM": syscall.SIGTERM, "USR1": syscall.SIGUSR1,
	"USR2": syscall.SIGUSR2,
}

func (p *process) signal(name string) {
	sig, ok := sshSignals[strings.ToUpper(strings.TrimPrefix(name, "SIG"))]
	if !ok || p.exited.Load() {
		return
	}
	_ = syscall.Kill(-p.cmd.Process.Pid, sig)
}

// hangup delivers SIGHUP to the child's process group when the channel closes.
func (p *process) hangup() {
	if p.exited.Load() {
		return
	}
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGHUP)
}

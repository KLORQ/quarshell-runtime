//go:build linux

package sshserver

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func startServer(t *testing.T, cfg Config) (*ssh.Client, string) {
	t.Helper()
	if cfg.InitPath == "" {
		cfg.InitPath = filepath.Join(t.TempDir(), "cautem-init")
		if err := os.WriteFile(cfg.InitPath, []byte("#!/bin/sh\n[ \"$1\" = \"--\" ] || exit 99\nshift\nexec \"$@\"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if cfg.Shell == "" {
		cfg.Shell = "/bin/sh"
	}
	if cfg.Env == nil {
		cfg.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + t.TempDir(), "SECRET_FROM_HOST=nope"}
	}
	cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "ssh", "sshd.sock")
	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = srv.Serve(ln) }()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	cc, chans, reqs, err := ssh.NewClientConn(c, "sandbox", &ssh.ClientConfig{
		User:            "sandbox",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	return client, sock
}

func TestListenUnixPermissions(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "ssh", "sshd.sock")
	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %o, want 600", got)
	}
	di, err := os.Stat(filepath.Dir(sock))
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Fatalf("dir mode = %o, want 700", got)
	}
}

func TestListenUnixReplacesStaleSocketOnly(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "sshd.sock")
	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	_ = os.WriteFile(sock, nil, 0o600) // ln.Close unlinks; simulate a planted regular file
	if _, err := ListenUnix(sock); err == nil {
		t.Fatal("expected refusal to replace a non-socket file")
	}
}

func TestExecOutputAndExitCode(t *testing.T) {
	client, _ := startServer(t, Config{})
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	sess.Stdout, sess.Stderr = &out, &errb
	err = sess.Run("echo hello; echo oops 1>&2; exit 3")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 3 {
		t.Fatalf("err = %v, want exit 3", err)
	}
	if strings.TrimSpace(out.String()) != "hello" || strings.TrimSpace(errb.String()) != "oops" {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errb.String())
	}
}

func TestExecStdin(t *testing.T) {
	client, _ := startServer(t, Config{})
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	sess.Stdin = strings.NewReader("piped-input\n")
	out, err := sess.Output("cat")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "piped-input" {
		t.Fatalf("out = %q", out)
	}
}

func TestEnvAllowlist(t *testing.T) {
	client, _ := startServer(t, Config{})
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Setenv("LC_WHALE", "ok"); err != nil {
		t.Fatalf("LC_* should be accepted: %v", err)
	}
	if err := sess.Setenv("LD_PRELOAD", "/tmp/evil.so"); err == nil {
		t.Fatal("LD_PRELOAD must be refused")
	}
	out, err := sess.Output(`printf '%s|%s' "$LC_WHALE" "$LD_PRELOAD"`)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "ok|" {
		t.Fatalf("out = %q", out)
	}
}

func TestPTYSession(t *testing.T) {
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skip("no /dev/ptmx")
	}
	client, _ := startServer(t, Config{})
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm-256color", 40, 120, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	out, err := sess.CombinedOutput(`tty; echo "$TERM"; stty size`)
	if err != nil {
		t.Fatalf("err=%v out=%q", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "/dev/pts/") || !strings.Contains(s, "xterm-256color") || !strings.Contains(s, "40 120") {
		t.Fatalf("pty output = %q", s)
	}
}

func TestRefusedSessionRequests(t *testing.T) {
	client, _ := startServer(t, Config{})
	for _, req := range []string{"auth-agent-req@openssh.com", "x11-req", "subsystem"} {
		sess, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte(nil)
		if req == "subsystem" {
			payload = ssh.Marshal(struct{ Name string }{"sftp"})
		}
		ok, err := sess.SendRequest(req, true, payload)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatalf("%s must be refused", req)
		}
		_ = sess.Close()
	}
}

func TestGlobalRequests(t *testing.T) {
	client, _ := startServer(t, Config{})
	fwd := ssh.Marshal(struct {
		Addr string
		Port uint32
	}{"0.0.0.0", 8080})
	if ok, _, _ := client.SendRequest("tcpip-forward", true, fwd); ok {
		t.Fatal("tcpip-forward (reverse forwarding) must be refused")
	}
	if ok, _, _ := client.SendRequest("streamlocal-forward@openssh.com", true, ssh.Marshal(struct{ Path string }{"/tmp/x"})); ok {
		t.Fatal("streamlocal-forward must be refused")
	}
	if ok, _, _ := client.SendRequest("keepalive@openssh.com", true, nil); !ok {
		t.Fatal("keepalive must succeed")
	}
}

func TestDirectTCPIPLoopbackOnly(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	client, _ := startServer(t, Config{})

	c, err := client.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("loopback forward: %v", err)
	}
	_, _ = c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	_ = c.Close()

	_, port, _ := net.SplitHostPort(echo.Addr().String())
	if c, err := client.Dial("tcp", "localhost:"+port); err != nil {
		t.Fatalf("localhost forward: %v", err)
	} else {
		_ = c.Close()
	}

	for _, target := range []string{"10.0.0.1:80", "169.254.169.254:80", "example.com:443"} {
		if c, err := client.Dial("tcp", target); err == nil {
			_ = c.Close()
			t.Fatalf("%s must be refused", target)
		}
	}

	for _, port := range []uint32{0, 70000} {
		payload := ssh.Marshal(directTCPIPPayload{Host: "127.0.0.1", Port: port, OrigHost: "127.0.0.1", OrigPort: 1})
		if ch, _, err := client.OpenChannel("direct-tcpip", payload); err == nil {
			_ = ch.Close()
			t.Fatalf("port %d must be refused", port)
		}
	}
}

func TestUnknownChannelRefused(t *testing.T) {
	client, _ := startServer(t, Config{})
	payload := ssh.Marshal(struct {
		Path     string
		Reserved string
		Port     uint32
	}{"/var/run/docker.sock", "", 0})
	if ch, _, err := client.OpenChannel("direct-streamlocal@openssh.com", payload); err == nil {
		_ = ch.Close()
		t.Fatal("direct-streamlocal must be refused")
	}
}

func TestChildrenWrappedByInit(t *testing.T) {
	dir := t.TempDir()
	initPath := filepath.Join(dir, "cautem-init")
	script := "#!/bin/sh\n[ \"$1\" = \"--\" ] || exit 99\nshift\necho wrapped\nexec \"$@\"\n"
	if err := os.WriteFile(initPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	client, _ := startServer(t, Config{InitPath: initPath})
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("echo inner")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "wrapped\ninner\n" {
		t.Fatalf("out = %q", out)
	}
}

func TestChildArgv(t *testing.T) {
	initPath := filepath.Join(t.TempDir(), "cautem-init")
	if err := os.WriteFile(initPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	srv := &Server{cfg: Config{Shell: "/bin/bash", InitPath: initPath}}
	ss := &session{srv: srv}
	argv, err := ss.childArgv("")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(argv, " "); got != initPath+" -- /bin/bash -l" {
		t.Fatalf("shell argv = %q", got)
	}
	argv, err = ss.childArgv("ls")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(argv, " "); got != initPath+" -- /bin/bash -lc ls" {
		t.Fatalf("exec argv = %q", got)
	}
	ss.env = []string{EnvNoLoginShell + "=1"}
	argv, err = ss.childArgv("ls")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(argv, " "); got != initPath+" -- /bin/bash -c ls" {
		t.Fatalf("no-login argv = %q", got)
	}
	ss.srv.cfg.InitPath = filepath.Join(t.TempDir(), "missing-init")
	if _, err := ss.childArgv("id"); err == nil {
		t.Fatal("configured but missing hardening init must fail closed")
	}
}

func TestNewRequiresExecutableHardeningInit(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("SSH server accepted an empty hardening init path")
	}
	if _, err := New(Config{InitPath: filepath.Join(t.TempDir(), "missing-init")}); err == nil {
		t.Fatal("SSH server accepted a missing hardening init")
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1": true, "127.1.2.3": true, "::1": true, "[::1]": true, "localhost": true, "LOCALHOST": true,
		"0.0.0.0": false, "10.0.0.1": false, "example.com": false, "localhost.evil.com": false, "": false,
	} {
		if got := IsLoopbackHost(host); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

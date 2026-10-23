package relaytarget

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServerRelaysLoopbackTCP(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	tempDir, err := os.MkdirTemp("", "wst-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	socket := filepath.Join(tempDir, "f.sock")
	server, err := Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "tcp://"+echo.Addr().String()+"\n"); err != nil {
		t.Fatal(err)
	}
	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || response != "OK\n" {
		t.Fatalf("dial acknowledgement=%q err=%v", response, err)
	}
	const payload = "sandbox-side-loopback"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != payload {
		t.Fatalf("echo=%q err=%v", got, err)
	}
}

func TestServerRejectsNonLoopbackTarget(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wst-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	socket := filepath.Join(tempDir, "f.sock")
	server, err := Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "tcp://192.0.2.1:80\n"); err != nil {
		t.Fatal(err)
	}
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || got != "ERR invalid target\n" {
		t.Fatalf("rejected target response=%q err=%v", got, err)
	}
}

func TestListenRefusesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "forward.sock")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path); err == nil {
		t.Fatal("Listen accepted an existing regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "preserve" {
		t.Fatalf("existing file data=%q err=%v", data, err)
	}
}

func TestListenRefusesToReplaceActiveSocket(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wst-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	socket := filepath.Join(tempDir, "f.sock")
	first, err := Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := Listen(socket); err == nil {
		t.Fatal("second server replaced an active socket")
	}
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatalf("original socket was replaced or removed: %v", err)
	}
	_ = conn.Close()
}

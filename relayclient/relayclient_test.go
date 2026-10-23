package relayclient

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRunRequiresOpenShellGRPCEndpoint(t *testing.T) {
	err := Run(context.Background(), Config{GatewayURL: "http://127.0.0.1:1", Sandbox: "demo", Token: "token"})
	if err == nil || !strings.Contains(err.Error(), "OpenShell gRPC endpoint is required") {
		t.Fatalf("Run() error = %v, want required native gRPC endpoint", err)
	}
}

func TestDialRelayTargetOnlyAllowsSSHAndLoopbackTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
			accepted <- struct{}{}
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialRelayTarget(ctx, "", "tcp://127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("dial loopback target: %v", err)
	}
	_ = conn.Close()
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("loopback target was not dialed")
	}

	for _, target := range []string{
		"tcp://example.com:80", "tcp://127.0.0.1:0", "tcp://127.0.0.1:70000",
		"tcp://0.0.0.0:80", "tcp://127.0.0.1.evil:80", "udp://127.0.0.1:80",
		"tcp://user@127.0.0.1:80", "tcp://127.0.0.1:80/path",
	} {
		if conn, err := dialRelayTarget(context.Background(), "", target); err == nil {
			_ = conn.Close()
			t.Errorf("dialRelayTarget(%q) accepted a non-loopback or malformed target", target)
		}
	}
}

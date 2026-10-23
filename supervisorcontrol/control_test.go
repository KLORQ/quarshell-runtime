package supervisorcontrol

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVMControlProtocolMatchesEmbeddedBundleContract(t *testing.T) {
	version, err := strconv.ParseUint(strings.TrimSpace(protocolVersionContract), 10, 32)
	if err != nil || version != uint64(VMControlProtocol) {
		t.Fatalf("embedded VM control protocol=%q, constant=%d, err=%v", protocolVersionContract, VMControlProtocol, err)
	}
}

func testSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(os.TempDir(), "sc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

func TestCallRoundTripsAndServerRemovesSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	path := testSocketPath(t)
	server, err := Start(ctx, path, func(_ context.Context, request Request) Response {
		if request.Operation != OperationReport || request.InstanceID != "instance-a" || request.ExitCode != 7 {
			return Response{Error: "unexpected lifecycle request"}
		}
		return Response{InstanceID: "instance-a"}
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("control socket stat: %v", err)
	}
	response, err := Call(context.Background(), path, Request{Operation: OperationReport, InstanceID: "instance-a", ExitCode: 7})
	if err != nil || response.InstanceID != "instance-a" {
		t.Fatalf("Call=(%+v,%v)", response, err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket after Close error=%v; want not-exist", err)
	}
}

func TestStartRejectsActiveAndNonSocketPaths(t *testing.T) {
	path := testSocketPath(t)
	server, err := Start(context.Background(), path, func(context.Context, Request) Response { return Response{} })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Start(context.Background(), path, func(context.Context, Request) Response { return Response{} }); err == nil {
		t.Fatal("Start replaced an active control socket")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(context.Background(), path, func(context.Context, Request) Response { return Response{} }); err == nil {
		t.Fatal("Start replaced a non-socket path")
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "keep" {
		t.Fatalf("non-socket path content=%q err=%v", body, err)
	}
}

func TestCallHonorsDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	path := testSocketPath(t)
	server, err := Start(ctx, path, func(ctx context.Context, _ Request) Response {
		<-ctx.Done()
		return Response{Error: "cancelled"}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = server.Close() }()
	callCtx, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer stop()
	if _, err := Call(callCtx, path, Request{Operation: OperationBegin}); err == nil {
		t.Fatal("Call unexpectedly ignored its deadline")
	}
}

func TestPeerGuardBindsClaimsAndRejectsReplay(t *testing.T) {
	identity := "spiffe://cautem.vm/sandbox/sandbox-a/session/11234567-89ab-cdef-0123-456789abcdef/rootfs/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/runtime/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/generation/0123456789abcdef0123456789abcdef"
	parsed, err := ParseVMIdentity(identity)
	if err != nil || parsed.SessionID != "11234567-89ab-cdef-0123-456789abcdef" {
		t.Fatalf("ParseVMIdentity() = (%+v, %v), want session-bound identity", parsed, err)
	}
	legacyIdentity := "spiffe://cautem.vm/sandbox/sandbox-a/rootfs/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/runtime/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/generation/0123456789abcdef0123456789abcdef"
	if _, err := ParseVMIdentity(legacyIdentity); err == nil {
		t.Fatal("legacy identity without session was accepted")
	}
	guard, err := NewPeerGuard(identity)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := newPeerClaims(identity)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Operation: OperationBegin, Peer: &claims}
	if err := guard.Validate(request); err != nil {
		t.Fatalf("first request rejected: %v", err)
	}
	if err := guard.Validate(request); err == nil {
		t.Fatal("replayed request was accepted")
	}
	wrongSession, err := newPeerClaims(identity)
	if err != nil {
		t.Fatal(err)
	}
	wrongSession.SessionID = "21234567-89ab-cdef-0123-456789abcdef"
	if err := guard.Validate(Request{Peer: &wrongSession}); err == nil {
		t.Fatal("request with mismatched session was accepted")
	}
	wrong, err := newPeerClaims(identity)
	if err != nil {
		t.Fatal(err)
	}
	wrong.RuntimeDigest = "sha256:other"
	if err := guard.Validate(Request{Peer: &wrong}); err == nil {
		t.Fatal("request with mismatched runtime digest was accepted")
	}
	wrong, err = newPeerClaims(identity)
	if err != nil {
		t.Fatal(err)
	}
	wrong.Protocol++
	if err := guard.Validate(Request{Peer: &wrong}); err == nil {
		t.Fatal("unsupported protocol version was accepted")
	}
	wrong, err = newPeerClaims(identity)
	if err != nil {
		t.Fatal(err)
	}
	wrong.IssuedAt = time.Now().Add(-2 * peerClaimsClockSkew).UnixMilli()
	if err := guard.Validate(Request{Peer: &wrong}); err == nil {
		t.Fatal("expired claims were accepted")
	}
}

func TestParseVMIdentityAcceptsOpenShellRuntimeGeneration(t *testing.T) {
	identity := "spiffe://cautem.vm/sandbox/sandbox-a/session/11234567-89ab-cdef-0123-456789abcdef/rootfs/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/runtime/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/generation/g0000000000000001"
	parsed, err := ParseVMIdentity(identity)
	if err != nil || parsed.Generation != "g0000000000000001" {
		t.Fatalf("ParseVMIdentity() = (%+v, %v), want OpenShell generation", parsed, err)
	}
	for _, generation := range []string{"g000000000000000z", "g000000000000001", "g00000000000000001"} {
		candidate := strings.TrimSuffix(identity, "g0000000000000001") + generation
		if _, err := ParseVMIdentity(candidate); err == nil {
			t.Errorf("ParseVMIdentity accepted malformed OpenShell generation %q", generation)
		}
	}
}

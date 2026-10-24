package relayclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	openshellv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/durationpb"
)

type refreshSessionServer struct {
	openshellv1.UnimplementedOpenShellServer
	refreshes atomic.Int32
}

type redirectSessionServer struct {
	openshellv1.UnimplementedOpenShellServer
	hello chan *openshellv1.SupervisorHello
}

func (s *redirectSessionServer) ConnectSupervisor(stream openshellv1.OpenShell_ConnectSupervisorServer) error {
	message, err := stream.Recv()
	if err != nil {
		return err
	}
	s.hello <- message.GetHello()
	return stream.Send(&openshellv1.GatewayMessage{Payload: &openshellv1.GatewayMessage_SessionRedirect{SessionRedirect: &openshellv1.SessionRedirect{PeerEndpoint: "https://gateway-b.example:7444", OwnerReplicaId: "gateway-b"}}})
}

func TestSupervisorSessionAdvertisesAndFollowsRedirectContract(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	backend := &redirectSessionServer{hello: make(chan *openshellv1.SupervisorHello, 1)}
	openshellv1.RegisterOpenShellServer(server, backend)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///bufconn", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cfg := Config{Sandbox: "sandbox-1", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err = supervisorSession(context.Background(), openshellv1.NewOpenShellClient(conn), cfg, "instance-1", 1, newSupervisorInstance("instance-1"), newSupervisorToken("sandbox-token"), newSupervisorToken("gateway-token"), true)
	var redirect *sessionRedirectError
	if !errors.As(err, &redirect) || redirect.endpoint != "https://gateway-b.example:7444" {
		t.Fatalf("session error = %v; want redirect to gateway-b", err)
	}
	select {
	case hello := <-backend.hello:
		if !hello.GetSupportsSessionRedirect() || !hello.GetRedirected() {
			t.Fatalf("hello = %+v; expected redirect capability and redirected marker", hello)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway did not receive supervisor hello")
	}
}

func (s *refreshSessionServer) ConnectSupervisor(stream openshellv1.OpenShell_ConnectSupervisorServer) error {
	message, err := stream.Recv()
	if err != nil {
		return err
	}
	if message.GetHello() == nil {
		return errMissingSupervisorHello
	}
	if err := stream.Send(&openshellv1.GatewayMessage{Payload: &openshellv1.GatewayMessage_SessionAccepted{SessionAccepted: &openshellv1.SessionAccepted{HeartbeatInterval: durationpb.New(60 * time.Second)}}}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func (s *refreshSessionServer) RefreshSandboxToken(context.Context, *openshellv1.RefreshSandboxTokenRequest) (*openshellv1.RefreshSandboxTokenResponse, error) {
	n := s.refreshes.Add(1)
	suffix := strconv.Itoa(int(n))
	return &openshellv1.RefreshSandboxTokenResponse{Token: "gateway-refreshed-" + suffix, SandboxToken: "sandbox-refreshed-" + suffix}, nil
}

var errMissingSupervisorHello = errors.New("missing supervisor hello")

func TestCompatSessionRefreshesSupervisorToken(t *testing.T) {
	const bufferSize = 1 << 20
	listener := bufconn.Listen(bufferSize)
	server := grpc.NewServer()
	backend := &refreshSessionServer{}
	openshellv1.RegisterOpenShellServer(server, backend)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	conn, err := grpc.NewClient("passthrough:///bufconn", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := openshellv1.NewOpenShellClient(conn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance := newSupervisorInstance("instance-1")
	token := newSupervisorToken("initial-token")
	gatewayToken := newSupervisorToken("gateway-initial-token")
	refreshedPair := make(chan [2]string, 4)
	cfg := Config{
		Sandbox: "sandbox-1", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), TokenRefreshInterval: 20 * time.Millisecond,
		OnCredentialsRefreshed: func(gatewayToken, sandboxToken string) error {
			refreshedPair <- [2]string{gatewayToken, sandboxToken}
			return nil
		},
	}
	done := make(chan error, 1)
	go func() {
		done <- supervisorSession(ctx, client, cfg, "instance-1", 1, instance, token, gatewayToken, false)
	}()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for backend.refreshes.Load() < 2 {
		select {
		case err := <-done:
			t.Fatalf("supervisorSession returned before refreshing the token: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for supervisor token refreshes")
		case <-ticker.C:
		}
	}
	if got := token.get(); got == "initial-token" || !strings.HasPrefix(got, "sandbox-refreshed-") {
		t.Fatalf("supervisor token = %q; refresh must select SandboxToken", got)
	}
	if got := gatewayToken.get(); got == "gateway-initial-token" || !strings.HasPrefix(got, "gateway-refreshed-") {
		t.Fatalf("Gateway token = %q; refresh must retain the Gateway bearer separately", got)
	}
	select {
	case pair := <-refreshedPair:
		if !strings.HasPrefix(pair[0], "gateway-refreshed-") || !strings.HasPrefix(pair[1], "sandbox-refreshed-") {
			t.Fatalf("refreshed credential pair = %q, want Gateway and Sandbox bearers", pair)
		}
	case <-time.After(time.Second):
		t.Fatal("supervisor credential refresh callback was not called")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("supervisorSession did not stop after context cancellation")
	}
}

package relayclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	openshellv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	policyStatusInitialRetry = time.Second
	policyStatusMaxRetry     = 32 * time.Second
	policyStatusRPCTimeout   = 10 * time.Second
)

// ReportPolicyStatus acknowledges the policy revision applied by the proxy
// sidecar. It uses the same sandbox bearer and guest TLS identity as Run.
func ReportPolicyStatus(ctx context.Context, cfg Config, revision uint32, loadError string) error {
	if revision == 0 {
		return fmt.Errorf("relayclient: policy revision is required")
	}
	target, secure, err := grpcTarget(firstNonEmpty(cfg.GatewayGRPCEndpoint, cfg.GatewayURL))
	if err != nil {
		return err
	}
	transport := credentials.TransportCredentials(insecure.NewCredentials())
	if secure {
		tlsConfig := cfg.TLSConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		transport = credentials.NewTLS(tlsConfig.Clone())
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(transport))
	if err != nil {
		return fmt.Errorf("relayclient: policy status connection failed: %w", err)
	}
	defer conn.Close()
	callCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+cfg.Token)
	statusValue := openshellv1.PolicyStatus_POLICY_STATUS_LOADED
	if strings.TrimSpace(loadError) != "" {
		statusValue = openshellv1.PolicyStatus_POLICY_STATUS_FAILED
	}
	_, err = openshellv1.NewOpenShellClient(conn).ReportPolicyStatus(callCtx, &openshellv1.ReportPolicyStatusRequest{
		SandboxId: cfg.Sandbox,
		Version:   revision,
		Status:    statusValue,
		LoadError: loadError,
	})
	return err
}

// ReportPolicyStatusUntilAck retries transient transport and server failures
// until the gateway acknowledges the revision, ctx is cancelled, or a terminal
// RPC error occurs. Callers that own an ordered status queue should invoke this
// serially so revisions cannot overtake each other.
func ReportPolicyStatusUntilAck(ctx context.Context, cfg Config, revision uint32, loadError string) error {
	if revision == 0 {
		return fmt.Errorf("relayclient: policy revision is required")
	}
	delay := policyStatusInitialRetry
	for {
		attemptCtx, cancel := context.WithTimeout(ctx, policyStatusRPCTimeout)
		err := ReportPolicyStatus(attemptCtx, cfg, revision, loadError)
		cancel()
		if err == nil || !retryablePolicyStatusError(err) {
			return err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		delay *= 2
		if delay > policyStatusMaxRetry {
			delay = policyStatusMaxRetry
		}
	}
}

func retryablePolicyStatusError(err error) bool {
	if err == nil {
		return false
	}
	code := status.Code(err)
	switch code {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Aborted, codes.Internal, codes.Unknown:
		return true
	case codes.OK:
		return false
	case codes.InvalidArgument, codes.NotFound, codes.AlreadyExists, codes.PermissionDenied, codes.Unauthenticated, codes.FailedPrecondition, codes.OutOfRange, codes.Unimplemented, codes.DataLoss, codes.Canceled:
		return false
	default:
		return true
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

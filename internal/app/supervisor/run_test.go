//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package supervisor

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-runtime/relaytarget"
	"github.com/KLORQ/quarshell-runtime/supervisorcontrol"
)

func TestValidateGatewayVerificationKeyFileConsumesPrivateEd25519KeySet(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("VM guest verification-key file ownership is a Unix/Linux contract")
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	privateDir := filepath.Join(t.TempDir(), "supervisor-control-private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateDir, "gateway-verification-keys.json")
	encoded, err := json.Marshal([]gatewayVerificationKey{{KeyID: "session-v1", PublicKeyPEM: publicPEM}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateGatewayVerificationKeyFile(path, "openshell", privateDir); err != nil {
		t.Fatalf("valid key set rejected: %v", err)
	}

	for _, invalid := range []string{
		`[{"key_id":"session-v1","key_id":"shadow","public_key_pem":` + strconv.Quote(publicPEM) + `}]`,
		`[{"key_id":"session-v1","public_key_pem":"not a PEM"}]`,
		`[{"key_id":"session-v1","public_key_pem":` + strconv.Quote(publicPEM) + `,"extra":true}]`,
	} {
		if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validateGatewayVerificationKeyFile(path, "openshell", privateDir); err == nil {
			t.Fatalf("invalid key set accepted: %s", invalid)
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateGatewayVerificationKeyFile(path, "openshell", privateDir); err == nil {
		t.Fatal("world-readable key file accepted")
	}
	if err := validateGatewayVerificationKeyFile(filepath.Join(t.TempDir(), "gateway-verification-keys.json"), "openshell", privateDir); err == nil {
		t.Fatal("verification key path outside the mTLS private directory accepted")
	}
	if err := validateGatewayVerificationKeyFile(path, "open shell", privateDir); err == nil {
		t.Fatal("Gateway ID containing whitespace accepted")
	}
}

func TestParseArgsRequiresSeparatorAndPreservesArgv(t *testing.T) {
	if _, err := ParseArgs([]string{"sh", "-c", "echo unsafe"}); err == nil {
		t.Fatal("command without explicit separator was accepted")
	}
	got, err := ParseArgs([]string{"--", "sh", "-c", "printf '%s'", "a b"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sh", "-c", "printf '%s'", "a b"}
	if !slices.Equal(got, want) {
		t.Fatalf("argv=%q, want %q", got, want)
	}
}

func TestRunReturnsWorkloadExitCode(t *testing.T) {
	code, err := Run(workloadArgs(exitCommand(17)...))
	if err != nil || code != 17 {
		t.Fatalf("Run()=(%d,%v), want (17,nil)", code, err)
	}
}

func TestRunRejectsEmptyCommand(t *testing.T) {
	if code, err := Run(nil); err == nil || code != 2 {
		t.Fatalf("Run(nil)=(%d,%v), want usage error", code, err)
	}
}

func TestWorkloadEnvironmentDropsSupervisorControlCredentials(t *testing.T) {
	privateValues := map[string]string{
		supervisorcontrol.EnvSocket:                 "/run/quarshell/control.sock",
		supervisorcontrol.EnvEndpoint:               "supervisor.default.svc:5502",
		supervisorcontrol.EnvClientCA:               "/run/quarshell/control/ca.pem",
		supervisorcontrol.EnvClientCert:             "/run/quarshell/control/tls.crt",
		supervisorcontrol.EnvClientKey:              "/run/quarshell/control/tls.key",
		supervisorcontrol.EnvPrivateDir:             "/untrusted/workload/override",
		supervisorcontrol.EnvListen:                 "0.0.0.0:5502",
		supervisorcontrol.EnvServerCA:               "/run/quarshell/control/server-ca.pem",
		supervisorcontrol.EnvServerCert:             "/run/quarshell/control/server.crt",
		supervisorcontrol.EnvServerKey:              "/run/quarshell/control/server.key",
		supervisorcontrol.EnvExpectedClientIdentity: "spiffe://quarshell.vm/sandbox/demo",
		relaytarget.EnvListen:                       "0.0.0.0:5503",
		relaytarget.EnvClientCA:                     "/run/quarshell/control/target-client-ca.pem",
		relaytarget.EnvServerCert:                   "/run/quarshell/control/target-server.crt",
		relaytarget.EnvServerKey:                    "/run/quarshell/control/target-server.key",
		relaytarget.EnvSSHSock:                      "/quarshell/ssh/sshd.sock",
		relaytarget.EnvServerCA:                     "/run/quarshell/control/target-server-ca.pem",
		relaytarget.EnvClientCert:                   "/run/quarshell/control/target-client.crt",
		relaytarget.EnvClientKey:                    "/run/quarshell/control/target-client.key",
		"QUARSHELL_RELAY_TARGET_SOCKET":             "/run/quarshell/target.sock",
		"QUARSHELL_MAIN_PROCESS_RESTART_POLICY":     "always",
		"QUARSHELL_GATEWAY_ID":                      "openshell",
		"QUARSHELL_GATEWAY_SANDBOX_ID":              "sandbox-a",
		"QUARSHELL_GATEWAY_VERIFICATION_KEYS_FILE":  "/run/quarshell/supervisor-control-private/gateway-verification-keys.json",
		"QUARSHELL_SANDBOX_PROTOCOL_TOKEN":          "private-sandbox-jwt",
		"QUARSHELL_SANDBOX_TOKEN":                   "private-gateway-jwt",
		"QUARSHELL_RUNTIME_GENERATION":              "g0000000000000001",
		"QUARSHELL_AUTH_EPOCH":                      "2",
		supervisorOTLPEndpointEnv:                   "http://collector:4317",
		supervisorTraceParentEnv:                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		supervisorTraceStateEnv:                     "vendor=value",
		"QUARSHELL_TEST_WORKLOAD_VALUE":             "visible",
	}
	for name, value := range privateValues {
		t.Setenv(name, value)
	}

	privateDir := "/run/quarshell/control"
	got := workloadEnvironment(privateDir)
	joined := strings.Join(got, "\n")
	for _, name := range []string{
		supervisorcontrol.EnvSocket,
		supervisorcontrol.EnvEndpoint,
		supervisorcontrol.EnvListen,
		supervisorcontrol.EnvClientCA,
		supervisorcontrol.EnvClientCert,
		supervisorcontrol.EnvClientKey,
		supervisorcontrol.EnvServerCA,
		supervisorcontrol.EnvServerCert,
		supervisorcontrol.EnvServerKey,
		supervisorcontrol.EnvExpectedClientIdentity,
		relaytarget.EnvListen,
		relaytarget.EnvClientCA,
		relaytarget.EnvServerCert,
		relaytarget.EnvServerKey,
		relaytarget.EnvSSHSock,
		relaytarget.EnvServerCA,
		relaytarget.EnvClientCert,
		relaytarget.EnvClientKey,
		"QUARSHELL_RELAY_TARGET_SOCKET",
		"QUARSHELL_MAIN_PROCESS_RESTART_POLICY",
		"QUARSHELL_GATEWAY_ID",
		"QUARSHELL_GATEWAY_SANDBOX_ID",
		"QUARSHELL_GATEWAY_VERIFICATION_KEYS_FILE",
		"QUARSHELL_SANDBOX_PROTOCOL_TOKEN",
		"QUARSHELL_SANDBOX_TOKEN",
		"QUARSHELL_RUNTIME_GENERATION",
		"QUARSHELL_AUTH_EPOCH",
		supervisorOTLPEndpointEnv,
		supervisorTraceParentEnv,
		supervisorTraceStateEnv,
	} {
		if strings.Contains(joined, name+"=") {
			t.Errorf("workload environment leaked %s", name)
		}
	}
	if !strings.Contains(joined, "QUARSHELL_TEST_WORKLOAD_VALUE=visible") {
		t.Fatal("ordinary workload environment variable was removed")
	}
	if !strings.Contains(joined, supervisorcontrol.EnvPrivateDir+"="+privateDir) {
		t.Fatal("workload init did not receive the supervisor control credential isolation marker")
	}
}

func TestHasSandboxSessionEnvironmentDetectsPartialCredentialInjection(t *testing.T) {
	keys := []string{
		"QUARSHELL_GATEWAY_ID", "QUARSHELL_GATEWAY_SANDBOX_ID", "QUARSHELL_RUNTIME_GENERATION",
		"QUARSHELL_AUTH_EPOCH", "QUARSHELL_GATEWAY_VERIFICATION_KEYS_FILE", "QUARSHELL_SANDBOX_PROTOCOL_TOKEN",
	}
	previous := make(map[string]string, len(keys))
	wasSet := make(map[string]bool, len(keys))
	for _, key := range keys {
		value, ok := os.LookupEnv(key)
		previous[key], wasSet[key] = value, ok
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, key := range keys {
			if wasSet[key] {
				_ = os.Setenv(key, previous[key])
			} else {
				_ = os.Unsetenv(key)
			}
		}
	})
	if hasSandboxSessionEnvironment() {
		t.Fatal("empty supervisor environment was treated as a partial session")
	}
	if err := os.Setenv("QUARSHELL_SANDBOX_PROTOCOL_TOKEN", "partial-state"); err != nil {
		t.Fatal(err)
	}
	if !hasSandboxSessionEnvironment() {
		t.Fatal("partial supervisor session environment was not detected")
	}
}

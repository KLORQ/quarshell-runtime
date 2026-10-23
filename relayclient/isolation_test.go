package relayclient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/KLORQ/quarshell-core/isolation"
)

func TestValidateIsolationDescriptorBindsHostSupervisorIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("descriptor permission mode bits are POSIX-specific")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "isolation-descriptor.json")
	rootfsDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runtimeDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	session := "11234567-89ab-cdef-0123-456789abcdef"
	generation := "0123456789abcdef0123456789abcdef"
	raw, err := isolation.EncodeDescriptor(isolation.Descriptor{
		Version: isolation.DescriptorVersion, BackendName: "quarshell/vm", SandboxID: "sandbox-a",
		SessionID: session, Generation: generation, RootfsDigest: rootfsDigest,
		RuntimeDigest: runtimeDigest, Payload: json.RawMessage(`{"worker_id":"sandbox-a"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	identity := "spiffe://quarshell.vm/sandbox/sandbox-a/session/" + session + "/rootfs/" + rootfsDigest + "/runtime/" + runtimeDigest + "/generation/" + generation
	cfg := Config{Sandbox: "sandbox-logical", IsolationSandboxID: "sandbox-a", IsolationDescriptorPath: path, AdmittedIsolationBackend: "quarshell/vm", SupervisorControlExpectedIdentity: identity}
	if err := validateIsolationDescriptor(cfg); err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}
	cfg.AdmittedIsolationBackend = "other/vm"
	if err := validateIsolationDescriptor(cfg); err == nil {
		t.Fatal("descriptor for a non-admitted backend was accepted")
	}
	cfg.AdmittedIsolationBackend = "quarshell/vm"
	cfg.SupervisorControlExpectedIdentity = "spiffe://quarshell.vm/sandbox/other/session/" + session + "/rootfs/" + rootfsDigest + "/runtime/" + runtimeDigest + "/generation/" + generation
	if err := validateIsolationDescriptor(cfg); err == nil {
		t.Fatal("identity for another sandbox was accepted")
	}
	cfg.SupervisorControlExpectedIdentity = identity
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateIsolationDescriptor(cfg); err == nil {
		t.Fatal("public descriptor permissions were accepted")
	}
}

func TestValidateIsolationDescriptorRequiredForVMIdentity(t *testing.T) {
	cfg := Config{SupervisorControlExpectedIdentity: "spiffe://quarshell.vm/sandbox/sandbox-a"}
	if err := validateIsolationDescriptor(cfg); err == nil {
		t.Fatal("VM identity without driver descriptor was accepted")
	}
}

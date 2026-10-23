package wsinit

import (
	"reflect"
	"testing"
)

func TestWorkloadEnvironmentStripsSupervisorOnlyControlAndCompatVariables(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"QUARSHELL_SUPERVISOR_CONTROL_SOCKET=/run/control.sock",
		"QUARSHELL_SUPERVISOR_CONTROL_ENDPOINT=supervisor.default.svc:5502",
		"QUARSHELL_SUPERVISOR_CONTROL_CLIENT_CA=/run/control/ca.pem",
		"QUARSHELL_SUPERVISOR_CONTROL_CLIENT_CERT=/run/control/client.crt",
		"QUARSHELL_SUPERVISOR_CONTROL_CLIENT_KEY=/run/control/client.key",
		"QUARSHELL_SUPERVISOR_CONTROL_PRIVATE_DIR=/run/control",
		"QUARSHELL_SUPERVISOR_CONTROL_SERVER_CA=/run/control/server-ca.pem",
		"QUARSHELL_SUPERVISOR_CONTROL_SERVER_CERT=/run/control/server.crt",
		"QUARSHELL_SUPERVISOR_CONTROL_SERVER_KEY=/run/control/server.key",
		"QUARSHELL_SUPERVISOR_CONTROL_EXPECTED_CLIENT_IDENTITY=spiffe://quarshell.vm/sandbox/demo",
		"QUARSHELL_RELAY_TARGET_LISTEN=0.0.0.0:5503",
		"QUARSHELL_RELAY_TARGET_CLIENT_CA=/run/control/client-ca.pem",
		"QUARSHELL_RELAY_TARGET_SERVER_CERT=/run/control/server.crt",
		"QUARSHELL_RELAY_TARGET_SERVER_KEY=/run/control/server.key",
		"QUARSHELL_RELAY_TARGET_SSH_SOCKET=/quarshell/ssh/sshd.sock",
		"QUARSHELL_RELAY_TARGET_ENDPOINT=workload.default.svc:5503",
		"QUARSHELL_RELAY_TARGET_SERVER_CA=/run/control/target-ca.pem",
		"QUARSHELL_RELAY_TARGET_CLIENT_CERT=/run/control/client.crt",
		"QUARSHELL_RELAY_TARGET_CLIENT_KEY=/run/control/client.key",
		"QUARSHELL_RELAY_TARGET_SOCKET=/run/control/target.sock",
		"QUARSHELL_SUPERVISOR_WAIT_FOR_HOST_START=1",
		"QUARSHELL_SUPERVISOR_START_GATE_FILE=/run/control/workload-start-gate",
		"QUARSHELL_SUPERVISOR_START_GATE_FD=4",
		"OPENSHELL_SANDBOX_UID=1000",
		"OPENSHELL_SANDBOX_GID=1000",
		"OPENSHELL_SANDBOX_TOKEN=secret",
		"OPENSHELL_TLS_KEY=/run/secrets/key",
		"OPENSHELL_NETWORK_RUNTIME_CAPABILITIES=policy-dns-transparent-tcp",
		"OPENSHELL_USER_ENVIRONMENT={}",
		"OPENAI_API_KEY=workload-secret",
	}
	want := []string{
		"PATH=/usr/bin",
		"OPENSHELL_USER_ENVIRONMENT={}",
		"OPENAI_API_KEY=workload-secret",
	}
	if got := workloadEnvironment(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("workloadEnvironment() = %v, want %v", got, want)
	}
}

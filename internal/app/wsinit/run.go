// Package wsinit is the composition root for cautem-init.
package wsinit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/KLORQ/quarshell-core/policy"
	"github.com/KLORQ/quarshell-runtime/internal/harden"
	"github.com/KLORQ/quarshell-runtime/supervisorcontrol"
)

func Run(args []string) error {
	policyPath := os.Getenv("CAUTEM_POLICY")
	mode := harden.Mode("")
	probe := false
	noDrop := false
	var cmd []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			i++
			if i >= len(args) {
				return fmt.Errorf("cautem-init: --policy needs a value")
			}
			policyPath = args[i]
		case "--mode":
			i++
			if i >= len(args) {
				return fmt.Errorf("cautem-init: --mode needs a value")
			}
			mode = harden.Mode(args[i])
		case "--probe":
			probe = true
		case "--no-drop":
			noDrop = true
		case "--":
			cmd = args[i+1:]
			i = len(args)
		case "-h", "--help":
			fmt.Fprintf(os.Stderr, "usage: cautem-init [--probe] [--policy PATH] [--mode best_effort|required] [--no-drop] -- <cmd>...\n")
			return nil
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("cautem-init: unknown flag %q", args[i])
			}
			cmd = args[i:]
			i = len(args)
		}
	}

	if probe {
		res := harden.Probe()
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		if res.LandlockABI == 0 && res.LandlockError != "" {
			os.Exit(2)
		}
		return nil
	}

	var doc policy.Document
	if policyPath != "" {
		abs, err := filepath.Abs(policyPath)
		if err != nil {
			return err
		}
		doc, err = policy.Load(abs)
		if err != nil {
			return fmt.Errorf("cautem-init: policy: %w", err)
		}
		if err := doc.Validate(); err != nil {
			return fmt.Errorf("cautem-init: policy: %w", err)
		}
	} else {
		doc = policy.Document{Version: 1}
	}
	if mode == "" {
		mode = harden.ModeFromPolicy(doc)
	}
	privateCredentialDir := strings.TrimSpace(os.Getenv(supervisorcontrol.EnvPrivateDir))
	if strings.TrimSpace(os.Getenv(supervisorcontrol.EnvEndpoint)) != "" || strings.TrimSpace(os.Getenv(supervisorcontrol.EnvSocket)) != "" {
		client, err := supervisorcontrol.NewClientFromEnvironment()
		if err != nil {
			return fmt.Errorf("cautem-init: supervisor control credentials: %w", err)
		}
		if privateCredentialDir == "" {
			privateCredentialDir = client.PrivateCredentialDir()
		}
	}

	res, err := harden.Apply(context.Background(), harden.Options{
		Doc:                  doc,
		Mode:                 mode,
		Log:                  os.Stderr,
		NoDrop:               noDrop,
		PrivateCredentialDir: privateCredentialDir,
	})
	if err != nil {
		return fmt.Errorf("cautem-init: apply hardening policy %q (landlock.compatibility=%s): %w", policyPath, doc.HardenMode(), err)
	}
	_ = res

	if len(cmd) == 0 {
		return fmt.Errorf("cautem-init: missing command (use -- <cmd>...)")
	}
	bin, err := exec.LookPath(cmd[0])
	if err != nil {
		bin = cmd[0]
	}
	if err := signalSupervisorWorkloadReady(); err != nil {
		return err
	}
	if err := waitForHostStartGate(); err != nil {
		return fmt.Errorf("cautem-init: host isolation start gate: %w", err)
	}
	return syscall.Exec(bin, cmd, workloadEnvironment(os.Environ()))
}

const hostStartGateFDEnv = "CAUTEM_SUPERVISOR_START_GATE_FD"

// waitForHostStartGate keeps workload-controlled instructions out of the
// guest until the VM driver confirms the ready isolation boundary.
func waitForHostStartGate() error {
	rawFD := strings.TrimSpace(os.Getenv(hostStartGateFDEnv))
	if rawFD == "" {
		return nil
	}
	_ = os.Unsetenv(hostStartGateFDEnv)
	fd, err := strconv.Atoi(rawFD)
	if err != nil || fd < 3 {
		return fmt.Errorf("start gate descriptor is invalid")
	}
	gate := os.NewFile(uintptr(fd), "host-workload-start-gate")
	if gate == nil {
		return fmt.Errorf("start gate descriptor is unavailable")
	}
	defer gate.Close()
	data, err := io.ReadAll(io.LimitReader(gate, 64))
	if err != nil {
		return fmt.Errorf("read start gate confirmation: %w", err)
	}
	if string(data) != "confirmed\n" {
		return fmt.Errorf("start gate confirmation is invalid")
	}
	return nil
}

const workloadReadyFDEnv = "CAUTEM_WORKLOAD_READY_FD"

func signalSupervisorWorkloadReady() error {
	raw := strings.TrimSpace(os.Getenv(workloadReadyFDEnv))
	if raw == "" {
		return nil
	}
	_ = os.Unsetenv(workloadReadyFDEnv)
	fd, err := strconv.Atoi(raw)
	if err != nil || fd < 3 {
		return fmt.Errorf("cautem-init: supervisor workload readiness descriptor is invalid")
	}
	file := os.NewFile(uintptr(fd), "supervisor-workload-ready")
	if file == nil {
		return fmt.Errorf("cautem-init: supervisor workload readiness descriptor is unavailable")
	}
	defer file.Close()
	message := fmt.Sprintf("1 %d %d\n", os.Getuid(), os.Getgid())
	if _, err := file.Write([]byte(message)); err != nil {
		return fmt.Errorf("cautem-init: signal supervisor workload readiness: %w", err)
	}
	return nil
}

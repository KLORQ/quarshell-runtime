// Package supervisor runs a sandbox workload as the container's PID 1.
//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package supervisor

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KLORQ/quarshell-core/defaults"
	"github.com/KLORQ/quarshell-runtime/relaytarget"
	"github.com/KLORQ/quarshell-runtime/supervisorcontrol"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type processEventMonitor interface {
	MainExit()
	Scan()
	ChildExit(pid int)
	Close()
}

const (
	workloadReadyFDEnv      = "CAUTEM_WORKLOAD_READY_FD"
	waitForWorkloadReadyEnv = "CAUTEM_SUPERVISOR_WAIT_FOR_WORKLOAD_READY"
	hostStartGateFDEnv      = "CAUTEM_SUPERVISOR_START_GATE_FD"
)

// Run starts a parsed workload argv, forwards termination signals to its
// process group, reaps adopted children, and returns the workload exit code.
func Run(args []string) (int, error) {
	provider, tracer, parent, err := configureSupervisorTelemetry(context.Background(), os.Getenv(supervisorOTLPEndpointEnv), os.Getenv(supervisorTraceParentEnv), os.Getenv(supervisorTraceStateEnv))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cautem-supervisor: OTLP tracing disabled: %v\n", err)
	}
	if provider != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), supervisorTelemetryShutdownTimeout)
			defer cancel()
			if err := provider.Shutdown(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "cautem-supervisor: OTLP tracer shutdown failed")
			}
		}()
	}
	if tracer != nil {
		_, span := tracer.Start(parent, "supervisor.run")
		code, runErr := runWorkload(args)
		if runErr != nil {
			span.SetAttributes(attribute.String("error.type", fmt.Sprintf("%T", runErr)))
			span.SetStatus(codes.Error, "supervisor failed")
		}
		span.SetAttributes(attribute.Int("process.exit.code", code))
		span.End()
		return code, runErr
	}
	return runWorkload(args)
}

func runWorkload(args []string) (int, error) {
	if len(args) == 0 {
		return 2, fmt.Errorf("usage: cautem-supervisor -- <command> [args...]")
	}
	controlClient, err := supervisorcontrol.NewClientFromEnvironment()
	if err != nil {
		return 125, fmt.Errorf("cautem-supervisor: configure lifecycle control: %w", err)
	}
	if err := controlClient.ConsumeClientCredentialKey(); err != nil {
		return 125, fmt.Errorf("cautem-supervisor: consume lifecycle bootstrap key: %w", err)
	}
	privateCredentialDir := controlClient.PrivateCredentialDir()
	if err := validateGatewayVerificationKeyFile(os.Getenv("CAUTEM_GATEWAY_VERIFICATION_KEYS_FILE"), os.Getenv("CAUTEM_GATEWAY_ID"), privateCredentialDir); err != nil {
		return 125, fmt.Errorf("cautem-supervisor: validate Gateway verification keys: %w", err)
	}
	if hasSandboxSessionEnvironment() {
		gatewayID := os.Getenv("CAUTEM_GATEWAY_ID")
		if gatewayID == "" || os.Getenv("CAUTEM_GATEWAY_SANDBOX_ID") == "" || os.Getenv("CAUTEM_RUNTIME_GENERATION") == "" || os.Getenv("CAUTEM_AUTH_EPOCH") == "" || os.Getenv("CAUTEM_GATEWAY_VERIFICATION_KEYS_FILE") == "" || os.Getenv("CAUTEM_SANDBOX_PROTOCOL_TOKEN") == "" {
			return 125, errors.New("cautem-supervisor: Gateway Sandbox Protocol session environment is incomplete")
		}
		if err := verifyGatewaySandboxToken(os.Getenv("CAUTEM_SANDBOX_PROTOCOL_TOKEN"), gatewayID, os.Getenv("CAUTEM_GATEWAY_SANDBOX_ID"), os.Getenv("CAUTEM_RUNTIME_GENERATION"), os.Getenv("CAUTEM_AUTH_EPOCH"), os.Getenv("CAUTEM_GATEWAY_VERIFICATION_KEYS_FILE"), privateCredentialDir, time.Now()); err != nil {
			return 125, fmt.Errorf("cautem-supervisor: verify Gateway Sandbox Protocol session: %w", err)
		}
	}
	targetSocket := strings.TrimSpace(os.Getenv("CAUTEM_RELAY_TARGET_SOCKET"))
	targetListen := strings.TrimSpace(os.Getenv(relaytarget.EnvListen))
	if targetSocket != "" && targetListen != "" {
		return 125, errors.New("cautem-supervisor: configure either a Unix target socket or an mTLS target listener")
	}
	var targetTLS *tls.Config
	if targetListen != "" {
		var targetCredentialDir string
		targetTLS, targetCredentialDir, err = relaytarget.ServerTLSConfigFromEnvironment()
		if err != nil {
			return 125, fmt.Errorf("cautem-supervisor: configure mTLS target bridge: %w", err)
		}
		if privateCredentialDir == "" || privateCredentialDir != targetCredentialDir {
			return 125, errors.New("cautem-supervisor: target bridge credentials must share the private lifecycle credential directory")
		}
	} else if strings.TrimSpace(os.Getenv(relaytarget.EnvClientCA)) != "" || strings.TrimSpace(os.Getenv(relaytarget.EnvServerCert)) != "" || strings.TrimSpace(os.Getenv(relaytarget.EnvServerKey)) != "" {
		return 125, errors.New("cautem-supervisor: target bridge server credentials require an mTLS listener")
	}
	if privateCredentialDir != "" {
		if err := protectSupervisorMemory(); err != nil {
			return 125, fmt.Errorf("cautem-supervisor: protect private runtime credentials: %w", err)
		}
	}
	var targetServer *relaytarget.Server
	if targetListen != "" {
		sshSocket := strings.TrimSpace(os.Getenv(relaytarget.EnvSSHSock))
		if sshSocket == "" {
			sshSocket = defaults.GuestSSHSocket
		}
		targetServer, err = relaytarget.ListenTLS(targetListen, targetTLS, sshSocket)
	} else if targetSocket != "" {
		targetServer, err = relaytarget.Listen(targetSocket)
	}
	if err != nil {
		return 125, fmt.Errorf("cautem-supervisor: start relay target listener: %w", err)
	}
	if targetServer != nil {
		defer func() {
			if err := targetServer.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "cautem-supervisor: stop relay target listener: %v\n", err)
			}
		}()
	}
	restartPolicy, err := parseRestartPolicy(os.Getenv("CAUTEM_MAIN_PROCESS_RESTART_POLICY"))
	if err != nil {
		return 125, err
	}
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, syscall.SIGCHLD, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	if err := enableChildSubreaper(); err != nil {
		return 125, fmt.Errorf("cautem-supervisor: enable child reaping: %w", err)
	}
	readinessPublished := false
	for restart := 0; ; restart++ {
		instanceID := ""
		if controlClient != nil {
			instanceID, err = beginProcessInstance(controlClient)
			if err != nil {
				return 125, fmt.Errorf("cautem-supervisor: begin OpenShell process instance: %w", err)
			}
		}
		command := exec.Command(args[0], args[1:]...)
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
		command.Env = workloadEnvironment(privateCredentialDir)
		command.SysProcAttr = mainProcessSysProcAttr(os.Stdin)
		var readyReader, readyWriter *os.File
		var hostStartGate *os.File
		var initStartGateReader, initStartGateWriter *os.File
		waitForWorkloadReady := os.Getenv(waitForWorkloadReadyEnv) == "1"
		if restart == 0 {
			if rawFD := strings.TrimSpace(os.Getenv(hostStartGateFDEnv)); rawFD != "" {
				fd, parseErr := strconv.Atoi(rawFD)
				if parseErr != nil || fd < 3 {
					return 125, fmt.Errorf("cautem-supervisor: host start gate descriptor is invalid")
				}
				hostStartGate = os.NewFile(uintptr(fd), "host-workload-start-gate")
				if hostStartGate == nil {
					return 125, fmt.Errorf("cautem-supervisor: host start gate descriptor is unavailable")
				}
			}
		}
		if waitForWorkloadReady {
			readyReader, readyWriter, err = os.Pipe()
			if err != nil {
				if hostStartGate != nil {
					_ = hostStartGate.Close()
				}
				return 125, fmt.Errorf("cautem-supervisor: create workload readiness pipe: %w", err)
			}
			command.ExtraFiles = []*os.File{readyWriter}
			command.Env = append(command.Env, workloadReadyFDEnv+"=3")
		}
		if hostStartGate != nil {
			initStartGateReader, initStartGateWriter, err = os.Pipe()
			if err != nil {
				if readyReader != nil {
					_ = readyReader.Close()
					_ = readyWriter.Close()
				}
				_ = hostStartGate.Close()
				return 125, fmt.Errorf("cautem-supervisor: create guest init start gate: %w", err)
			}
			gateFD := 3 + len(command.ExtraFiles)
			command.ExtraFiles = append(command.ExtraFiles, initStartGateReader)
			command.Env = append(command.Env, hostStartGateFDEnv+"="+strconv.Itoa(gateFD))
		}
		if err := command.Start(); err != nil {
			if readyReader != nil {
				_ = readyReader.Close()
				_ = readyWriter.Close()
			}
			if hostStartGate != nil {
				_ = hostStartGate.Close()
			}
			closeWorkloadStartGate(initStartGateReader)
			closeWorkloadStartGate(initStartGateWriter)
			return 127, fmt.Errorf("cautem-supervisor: start workload: %w", err)
		}
		if readyWriter != nil {
			_ = readyWriter.Close()
		}
		closeWorkloadStartGate(initStartGateReader)
		result := make(chan error, 1)
		go func() { result <- command.Wait() }()
		var waitErr error
		var processMonitor processEventMonitor
		shutdownRequested := false
		if waitForWorkloadReady {
			ready := make(chan error, 1)
			go func() {
				readyMessage, readErr := bufio.NewReader(io.LimitReader(readyReader, 128)).ReadString('\n')
				_ = readyReader.Close()
				if len(readyMessage) == 0 {
					ready <- errors.New("workload initializer exited before readiness")
					return
				}
				if readErr != nil {
					ready <- fmt.Errorf("workload initializer exited before readiness: %w", readErr)
					return
				}
				fields := strings.Fields(string(readyMessage))
				if len(fields) != 3 || fields[0] != "1" {
					ready <- errors.New("workload initializer sent an invalid readiness identity")
					return
				}
				uid, uidErr := strconv.ParseUint(fields[1], 10, 32)
				gid, gidErr := strconv.ParseUint(fields[2], 10, 32)
				if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
					ready <- errors.New("workload initializer sent an invalid readiness identity")
					return
				}
				ready <- publishSupervisorReadiness(uint32(uid), uint32(gid))
			}()
			select {
			case readyErr := <-ready:
				if readyErr != nil {
					closeWorkloadStartGate(hostStartGate)
					closeWorkloadStartGate(initStartGateWriter)
					_ = signalWorkloadGroup(command.Process.Pid, syscall.SIGKILL)
					<-result
					return 125, fmt.Errorf("cautem-supervisor: %w", readyErr)
				}
			case waitErr = <-result:
				closeWorkloadStartGate(hostStartGate)
				closeWorkloadStartGate(initStartGateWriter)
				// A short-lived initializer can publish readiness and exit before
				// this select runs. Once Wait has completed, the readiness reader
				// can now deterministically report either that message or EOF.
				if readyErr := <-ready; readyErr == nil {
					readinessPublished = true
					goto workloadExited
				}
				code, _ := workloadExitCode(waitErr)
				return 125, fmt.Errorf("cautem-supervisor: workload exited before readiness (code %d)", code)
			}
		}
		if !readinessPublished {
			if !waitForWorkloadReady {
				err = publishSupervisorReadiness(0, 0)
			} else {
				err = nil // readiness was published by the validated initializer identity above
			}
			if err != nil {
				closeWorkloadStartGate(hostStartGate)
				closeWorkloadStartGate(initStartGateWriter)
				_ = signalWorkloadGroup(command.Process.Pid, syscall.SIGKILL)
				<-result
				return 125, err
			}
			readinessPublished = true
		}
		if hostStartGate != nil {
			if err := waitForHostStartGate(hostStartGate); err != nil {
				closeWorkloadStartGate(hostStartGate)
				closeWorkloadStartGate(initStartGateWriter)
				_ = signalWorkloadGroup(command.Process.Pid, syscall.SIGKILL)
				<-result
				return 125, fmt.Errorf("cautem-supervisor: host isolation start gate: %w", err)
			}
			closeWorkloadStartGate(hostStartGate)
			hostStartGate = nil
			if _, err := io.WriteString(initStartGateWriter, "confirmed\n"); err != nil {
				closeWorkloadStartGate(initStartGateWriter)
				_ = signalWorkloadGroup(command.Process.Pid, syscall.SIGKILL)
				<-result
				return 125, fmt.Errorf("cautem-supervisor: signal guest init start gate: %w", err)
			}
			closeWorkloadStartGate(initStartGateWriter)
			initStartGateWriter = nil
		}
		processMonitor = startProcessMonitor(controlClient, instanceID, command.Process.Pid, command.Path)
		for !shutdownRequested {
			select {
			case signal := <-signals:
				if signal == syscall.SIGCHLD {
					reapWorkloadChildren(command.Process.Pid, processMonitor)
					continue
				}
				shutdownRequested = true
				if err := signalWorkloadGroup(command.Process.Pid, signal); err != nil && !errors.Is(err, syscall.ESRCH) {
					fmt.Fprintf(os.Stderr, "cautem-supervisor: forward %s: %v\n", signal, err)
				}
			case waitErr = <-result:
				goto workloadExited
			}
		}
		waitErr = <-result
	workloadExited:
		code, resultErr := workloadExitCode(waitErr)
		if processMonitor != nil {
			processMonitor.MainExit()
		}
		stopWorkloadGroup(command.Process.Pid, processMonitor)
		if processMonitor != nil {
			processMonitor.Close()
			flushProcessEvents(controlClient, instanceID)
		}
		for {
			select {
			case signal := <-signals:
				if signal != syscall.SIGCHLD {
					shutdownRequested = true
				}
			default:
				goto signalsDrained
			}
		}
	signalsDrained:
		if shouldRestartMainProcess(restartPolicy, code, resultErr, shutdownRequested) {
			if !waitForRestart(signals, restartBackoff(restart)) {
				shutdownRequested = true
			}
			if !shutdownRequested {
				continue
			}
		}
		if controlClient != nil && instanceID != "" && !shutdownRequested && resultErr == nil {
			if err := reportProcessExitUntilAck(controlClient, instanceID, int32(code)); err != nil {
				return 125, err
			}
			if err := finalizeProcessExitUntilAck(controlClient, instanceID); err != nil {
				return 125, err
			}
		}
		return code, resultErr
	}
}

type mainProcessRestartPolicy uint8

const (
	mainProcessRestartNever mainProcessRestartPolicy = iota
	mainProcessRestartOnFailure
	mainProcessRestartAlways
)

func parseRestartPolicy(raw string) (mainProcessRestartPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "never":
		return mainProcessRestartNever, nil
	case "on-failure":
		return mainProcessRestartOnFailure, nil
	case "always":
		return mainProcessRestartAlways, nil
	default:
		return mainProcessRestartNever, fmt.Errorf("cautem-supervisor: invalid main process restart policy %q", raw)
	}
}

func shouldRestartMainProcess(policy mainProcessRestartPolicy, exitCode int, waitErr error, shutdown bool) bool {
	if shutdown || waitErr != nil {
		return false
	}
	switch policy {
	case mainProcessRestartAlways:
		return true
	case mainProcessRestartOnFailure:
		return exitCode != 0
	default:
		return false
	}
}

func restartBackoff(restart int) time.Duration {
	delay := 100 * time.Millisecond
	for i := 0; i < restart && delay < 5*time.Second; i++ {
		delay *= 2
	}
	if delay > 5*time.Second {
		return 5 * time.Second
	}
	return delay
}

func waitForRestart(signals chan os.Signal, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case signal := <-signals:
			if signal == syscall.SIGCHLD {
				continue
			}
			return false
		case <-timer.C:
			return true
		}
	}
}

func flushProcessEvents(controlClient *supervisorcontrol.Client, instanceID string) {
	if controlClient == nil || strings.TrimSpace(instanceID) == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	_, err := controlClient.Call(ctx, supervisorcontrol.Request{
		Operation: supervisorcontrol.OperationFlush, InstanceID: instanceID,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cautem-supervisor: final process events may not have reached the gateway: %v\n", err)
	}
}

func workloadExitCode(err error) (int, error) {
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			status, ok := exitErr.Sys().(syscall.WaitStatus)
			if ok {
				if status.Signaled() {
					return 128 + int(status.Signal()), nil
				}
				return status.ExitStatus(), nil
			}
		}
		return 125, fmt.Errorf("cautem-supervisor: wait for workload: %w", err)
	}
	return 0, nil
}

func beginProcessInstance(controlClient *supervisorcontrol.Client) (string, error) {
	deadline := time.Now().Add(30 * time.Second)
	delay := 100 * time.Millisecond
	for {
		// The host control handler waits for the replacement Gateway session
		// before acknowledging readiness; leave time for its 15-second bound.
		ctx, cancel := context.WithTimeout(context.Background(), 16*time.Second)
		response, err := controlClient.Call(ctx, supervisorcontrol.Request{Operation: supervisorcontrol.OperationBegin})
		cancel()
		if err == nil && response.InstanceID != "" {
			return response.InstanceID, nil
		}
		if time.Now().After(deadline) {
			if err == nil {
				err = errors.New("sidecar returned an empty instance id")
			}
			return "", err
		}
		time.Sleep(delay)
		if delay < time.Second {
			delay *= 2
		}
	}
}

func reportProcessExitUntilAck(controlClient *supervisorcontrol.Client, instanceID string, exitCode int32) error {
	return lifecycleUntilAck(controlClient, supervisorcontrol.Request{Operation: supervisorcontrol.OperationReport, InstanceID: instanceID, ExitCode: exitCode}, "report main process exit")
}

// waitForHostStartGate consumes the host-to-supervisor confirmation pipe. The
// supervisor relays it over a second pipe to cautem-init so process monitoring
// and the final workload exec share the same start ordering.
func waitForHostStartGate(file *os.File) error {
	if file == nil {
		return errors.New("host start gate descriptor is unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(file, 64))
	if err != nil {
		return fmt.Errorf("read host start gate: %w", err)
	}
	if string(data) != "confirmed\n" {
		return errors.New("host start gate confirmation is invalid")
	}
	return nil
}

func closeWorkloadStartGate(file *os.File) {
	if file != nil {
		_ = file.Close()
	}
}

func finalizeProcessExitUntilAck(controlClient *supervisorcontrol.Client, instanceID string) error {
	return lifecycleUntilAck(controlClient, supervisorcontrol.Request{Operation: supervisorcontrol.OperationFinalize, InstanceID: instanceID}, "finalize main process exit")
}

func lifecycleUntilAck(controlClient *supervisorcontrol.Client, request supervisorcontrol.Request, operation string) error {
	delay := 250 * time.Millisecond
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 16*time.Second)
		_, err := controlClient.Call(ctx, request)
		cancel()
		if err == nil {
			return nil
		}
		fmt.Fprintf(os.Stderr, "cautem-supervisor: %s failed; retrying: %v\n", operation, err)
		time.Sleep(delay)
		if delay < 2*time.Second {
			delay *= 2
		}
	}
}

func hasSandboxSessionEnvironment() bool {
	for _, key := range []string{
		"CAUTEM_GATEWAY_ID", "CAUTEM_GATEWAY_SANDBOX_ID", "CAUTEM_RUNTIME_GENERATION",
		"CAUTEM_AUTH_EPOCH", "CAUTEM_GATEWAY_VERIFICATION_KEYS_FILE", "CAUTEM_SANDBOX_PROTOCOL_TOKEN",
	} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}

func workloadEnvironment(privateCredentialDir string) []string {
	privateControlEnv := map[string]struct{}{
		"CAUTEM_MAIN_PROCESS_RESTART_POLICY":    {},
		"CAUTEM_SANDBOX_TOKEN":                  {},
		"CAUTEM_GATEWAY_ID":                     {},
		"CAUTEM_GATEWAY_SANDBOX_ID":             {},
		"CAUTEM_GATEWAY_VERIFICATION_KEYS_FILE": {},
		"CAUTEM_SANDBOX_PROTOCOL_TOKEN":         {},
		"CAUTEM_RUNTIME_GENERATION":             {},
		"CAUTEM_AUTH_EPOCH":                     {},
		supervisorOTLPEndpointEnv:               {},
		supervisorTraceParentEnv:                {},
		supervisorTraceStateEnv:                 {},
		workloadReadyFDEnv:                      {},
		waitForWorkloadReadyEnv:                 {},
		hostStartGateFDEnv:                      {},
		envSupervisorReadyFile:                  {},
		supervisorcontrol.EnvSocket:             {}, supervisorcontrol.EnvEndpoint: {}, supervisorcontrol.EnvListen: {},
		supervisorcontrol.EnvClientCA: {}, supervisorcontrol.EnvClientCert: {}, supervisorcontrol.EnvClientKey: {},
		supervisorcontrol.EnvPrivateDir: {},
		supervisorcontrol.EnvServerCA:   {}, supervisorcontrol.EnvServerCert: {}, supervisorcontrol.EnvServerKey: {},
		supervisorcontrol.EnvExpectedClientIdentity: {},
		relaytarget.EnvEndpoint:                     {}, relaytarget.EnvListen: {}, relaytarget.EnvClientCA: {},
		relaytarget.EnvServerCert: {}, relaytarget.EnvServerKey: {}, relaytarget.EnvSSHSock: {},
		relaytarget.EnvServerCA: {}, relaytarget.EnvClientCert: {}, relaytarget.EnvClientKey: {},
		"CAUTEM_RELAY_TARGET_SOCKET": {},
	}
	environment := os.Environ()
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if _, private := privateControlEnv[key]; !private {
			filtered = append(filtered, entry)
		}
	}
	if privateCredentialDir != "" {
		filtered = append(filtered, supervisorcontrol.EnvPrivateDir+"="+privateCredentialDir)
	}
	return filtered
}

// ParseArgs accepts only an explicit separator, preserving workload argv
// boundaries and ensuring supervisor flags cannot be confused with payload.
func ParseArgs(args []string) ([]string, error) {
	for i, arg := range args {
		if arg == "--" {
			if i+1 == len(args) {
				return nil, fmt.Errorf("cautem-supervisor: command after -- is empty")
			}
			return args[i+1:], nil
		}
	}
	return nil, fmt.Errorf("cautem-supervisor: expected -- before workload command")
}

const shutdownGrace = 2 * time.Second

const envSupervisorReadyFile = "CAUTEM_VM_SUPERVISOR_READY_FILE"

const supervisorReadyContents = "quarshell-supervisor-ready-v1\n"

func publishSupervisorReadiness(uid, gid uint32) error {
	path := strings.TrimSpace(os.Getenv(envSupervisorReadyFile))
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("cautem-supervisor: readiness file path must be absolute and clean")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("cautem-supervisor: publish readiness: %w", err)
	}
	contents := supervisorReadyContents
	if uid != 0 && gid != 0 {
		contents = fmt.Sprintf("quarshell-supervisor-ready-v2 %d %d\n", uid, gid)
	}
	if _, err := file.WriteString(contents); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("cautem-supervisor: write readiness: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("cautem-supervisor: sync readiness: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("cautem-supervisor: close readiness: %w", err)
	}
	return nil
}

func stopWorkloadGroup(pid int, monitor processEventMonitor) {
	_ = signalWorkloadGroup(pid, syscall.SIGTERM)
	deadline := time.NewTimer(shutdownGrace)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for processGroupExists(pid) {
		select {
		case <-ticker.C:
			reapWorkloadChildren(pid, monitor)
		case <-deadline.C:
			_ = signalWorkloadGroup(pid, syscall.SIGKILL)
			for processGroupExists(pid) {
				reapWorkloadChildren(pid, monitor)
				time.Sleep(10 * time.Millisecond)
			}
			return
		}
	}
}

// reapWorkloadChildren reconciles /proc before wait4 removes child entries.
// The wait4 callback lets the monitor emit EXIT for tracked adopted children
// immediately instead of waiting for the next periodic /proc scan.
func reapWorkloadChildren(pid int, monitor processEventMonitor) {
	if monitor != nil {
		monitor.Scan()
	}
	reapAdoptedChildren(pid, func(childPID int) {
		if monitor != nil {
			monitor.ChildExit(childPID)
		}
	})
}

//go:build linux

package harden

import (
	"fmt"
	"os"
	"strings"

	"github.com/KLORQ/quarshell-policy/corepolicy"
	ll "github.com/landlock-lsm/go-landlock/landlock"
	"golang.org/x/sys/unix"
)

const landlockCreateRulesetVersion = 1 << 0

func landlockABI() (int, error) {
	r1, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0, 0, landlockCreateRulesetVersion,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(r1), nil
}

func applyLandlock(doc policy.Document) error {
	abi, _ := landlockABI()
	return applyLandlockWithMode(doc, abi, ModeFromPolicy(doc))
}

func applyLandlockWithMode(doc policy.Document, kernelABI int, mode Mode) error {
	workdir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve active workspace for filesystem policy: %w", err)
	}
	reads, writes := filesystemPaths(doc, workdir)
	if doc.FilesystemPolicy == nil {
		// A sandbox must be able to execute the image's normal userland after
		// Landlock is installed. OpenShell's omitted filesystem_policy does not
		// make /bin, the dynamic linker, or /etc inaccessible. Without this
		// baseline, an otherwise empty policy causes execve(2) to fail with
		// EACCES (notably inside nested Docker/Podman).
		reads = append(reads, "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/proc")
		// Container entrypoints and ordinary tools expect /dev/null to remain
		// writable after the baseline is installed.
		writes = append(writes, "/dev/null")
		// /tmp is the image's conventional scratch area and is required by the
		// OpenShell exec contract for commands that exchange temporary state.
		writes = append(writes, "/tmp")
	}
	if doc.Display != nil && strings.EqualFold(doc.Display.Mode, "novnc") {
		reads = append(reads, "/tmp/.X11-unix", "/usr/share", "/usr/lib",
			"/etc/chromium", "/usr/lib/chromium", "/usr/bin/chromium")
		writes = append(writes, "/tmp/.X11-unix", "/tmp/quarshell-display", "/home", "/run/user")
	}
	reads = unique(reads)
	writes = unique(writes)

	profileABI := landlockProfileMaxABI(kernelABI)
	if mode == ModeRequired && profileABI < 3 {
		return fmt.Errorf("landlock ABI v3 or newer is required in hard_requirement mode; detected ABI %d", profileABI)
	}
	var cfg ll.Config
	if profileABI >= 7 {
		cfg = ll.V7.EnableLoggingForSubprocesses().BestEffort()
		if mode == ModeRequired {
			cfg = ll.V7.EnableLoggingForSubprocesses()
		}
	} else if mode == ModeRequired {
		switch profileABI {
		case 5:
			cfg = ll.V5
		case 4:
			cfg = ll.V4
		case 3:
			cfg = ll.V3
		case 2:
			cfg = ll.V2
		default:
			cfg = ll.V1
		}
	} else {
		cfg = ll.V5.BestEffort()
	}
	rules := make([]ll.PathOpt, 0, 4) //nolint:staticcheck // PathOpt kept until landlock major drop of alias
	roDirs, roFiles, err := existingByType(reads, mode)
	if err != nil {
		return err
	}
	if len(roDirs) > 0 {
		rules = append(rules, ll.RODirs(roDirs...))
	}
	if len(roFiles) > 0 {
		rules = append(rules, ll.ROFiles(roFiles...))
	}
	rwDirs, rwFiles, err := existingByType(writes, mode)
	if err != nil {
		return err
	}
	if len(rwDirs) > 0 {
		rules = append(rules, ll.RWDirs(rwDirs...))
	}
	if len(rwFiles) > 0 {
		rules = append(rules, ll.RWFiles(rwFiles...))
	}
	if len(rules) == 0 {
		if mode == ModeRequired {
			return fmt.Errorf("landlock.compatibility is hard_requirement but no filesystem paths are configured")
		}
		return nil
	}
	return cfg.RestrictPaths(rules...)
}

func existingByType(paths []string, mode Mode) (dirs, files []string, err error) {
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			if mode == ModeRequired {
				return nil, nil, fmt.Errorf("landlock path unavailable in hard_requirement mode: %s: %w", p, err)
			}
			continue
		}
		if info.IsDir() {
			dirs = append(dirs, p)
		} else {
			files = append(files, p)
		}
	}
	return dirs, files, nil
}

func unique(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

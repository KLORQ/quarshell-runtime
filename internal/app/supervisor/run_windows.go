//go:build windows

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

func Run(args []string) (int, error) {
	command, err := ParseArgs(args)
	if err != nil {
		return 2, err
	}
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), nil
		}
		return 127, fmt.Errorf("cautem-supervisor: run workload: %w", err)
	}
	return 0, nil
}

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

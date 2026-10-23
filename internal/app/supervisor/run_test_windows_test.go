//go:build windows

package supervisor

import "fmt"

func workloadArgs(args ...string) []string {
	return append([]string{"--"}, args...)
}

func exitCommand(code int) []string {
	return []string{"cmd", "/c", fmt.Sprintf("exit /b %d", code)}
}

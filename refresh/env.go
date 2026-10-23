package refresh

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// FromEnv refreshes credentials by reading current host environment values.
// Vault, OAuth and token-grant refresh strategies are separate compatibility gaps.
type FromEnv struct{}

// githubEnvKeys can be filled from `gh auth token` when the process env is empty
// (common: gh logged in via keyring, GITHUB_TOKEN unset).
var githubEnvKeys = map[string]struct{}{
	"GITHUB_TOKEN": {},
	"GH_TOKEN":     {},
}

// Refresh returns KEY/VAL pairs for keys present and non-empty in the process environ.
// For GITHUB_TOKEN / GH_TOKEN, falls back to `gh auth token` when env is unset.
func (FromEnv) Refresh(_ context.Context, keys []string) ([]Result, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("refresh: no keys")
	}
	out := make([]Result, 0, len(keys))
	var missing []string
	var ghTok string
	var ghTokErr error
	ghTokLoaded := false
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		v, ok := os.LookupEnv(k)
		if ok && strings.TrimSpace(v) != "" {
			out = append(out, Result{Key: k, Value: v})
			continue
		}
		if _, isGH := githubEnvKeys[k]; isGH {
			if !ghTokLoaded {
				ghTok, ghTokErr = ghAuthToken()
				ghTokLoaded = true
			}
			if ghTokErr == nil && strings.TrimSpace(ghTok) != "" {
				out = append(out, Result{Key: k, Value: ghTok})
				continue
			}
		}
		missing = append(missing, k)
	}
	if len(missing) > 0 && len(out) == 0 {
		return nil, fmt.Errorf("refresh: env keys not set: %s", strings.Join(missing, ","))
	}
	if len(missing) > 0 {
		return out, fmt.Errorf("refresh: partial — missing env: %s", strings.Join(missing, ","))
	}
	return out, nil
}

func ghAuthToken() (string, error) {
	cmd := exec.Command("gh", "auth", "token")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("gh auth token: %s", msg)
	}
	tok := strings.TrimSpace(stdout.String())
	if tok == "" {
		return "", fmt.Errorf("gh auth token: empty")
	}
	return tok, nil
}

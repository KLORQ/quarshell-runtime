// Package secrets defines a Store interface for credential backends.
// Gateway uses LocalEncrypted; the proxy sidecar resolves via gateway HTTP
// (GET /v1/sandboxes/{name}/secrets) into proxy.SecretStore for rewrite.
package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Store resolves secret values by key (env var name or vault path alias).
type Store interface {
	Get(ctx context.Context, key string) (string, error)
}

// MapStore is an in-memory Store (tests and proxy-sidecar maps).
type MapStore map[string]string

// Get returns the value or ErrNotFound.
func (m MapStore) Get(_ context.Context, key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", fmt.Errorf("secrets: empty key")
	}
	if m == nil {
		return "", ErrNotFound{Key: key}
	}
	v, ok := m[key]
	if !ok {
		return "", ErrNotFound{Key: key}
	}
	return v, nil
}

// EnvStore reads from process environment (or a provided environ slice).
type EnvStore struct {
	Environ []string // if nil, uses os.Environ()
}

// Get looks up KEY=VAL from Environ / os.Environ.
func (e EnvStore) Get(_ context.Context, key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", fmt.Errorf("secrets: empty key")
	}
	env := e.Environ
	if env == nil {
		env = os.Environ()
	}
	prefix := key + "="
	for _, line := range env {
		if after, ok := strings.CutPrefix(line, prefix); ok {
			return after, nil
		}
	}
	return "", ErrNotFound{Key: key}
}

// ErrNotFound means the key is absent.
type ErrNotFound struct {
	Key string
}

func (e ErrNotFound) Error() string {
	return fmt.Sprintf("secrets: key %q not found", e.Key)
}

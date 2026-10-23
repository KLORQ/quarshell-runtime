package secrets

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Well-known secrets paths / env (single source of truth — do not hardcode elsewhere).
const (
	EnvKEK    = "CAUTEM_SECRETS_KEK"
	FileKEK   = "secrets.kek"
	FileStore = "secrets.enc.json"
	kekBytes  = 32
)

// Source identifies where the active KEK came from.
type Source string

const (
	SourceEnv  Source = "env"
	SourceFile Source = "file"
	SourceNone Source = "none"
)

// Status describes KEK durability for doctor /gateway info.
// Pinned is true when CAUTEM_SECRETS_KEK is set (survives empty data-dir recreate
// as long as the same env is supplied). File-backed KEK survives volume recreate
// but is lost if the volume is deleted without a pinned env.
type Status struct {
	Source          Source `json:"source"`
	Pinned          bool   `json:"pinned"`
	Path            string `json:"path,omitempty"`
	Format          string `json:"format,omitempty"`
	MigrationNeeded bool   `json:"migration_needed,omitempty"`
}

// Inspect reports KEK status without creating files.
// getenv may be nil (defaults to os.Getenv).
func Inspect(dir string, getenv func(string) string) Status {
	if getenv == nil {
		getenv = os.Getenv
	}
	status := Status{}
	if strings.TrimSpace(getenv(EnvKEK)) != "" {
		status = Status{Source: SourceEnv, Pinned: true}
	} else {
		path := filepath.Join(dir, FileKEK)
		if st, err := os.Stat(path); err == nil && !st.IsDir() && st.Size() == int64(kekBytes) {
			status = Status{Source: SourceFile, Path: path}
		} else {
			status = Status{Source: SourceNone, Path: path}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, FileStore)); err == nil {
		var header struct {
			Version int    `json:"version"`
			Salt    string `json:"salt"`
		}
		if json.Unmarshal(raw, &header) == nil {
			switch header.Version {
			case 1:
				status.Format, status.MigrationNeeded = "v1-legacy", true
			case 2:
				if header.Salt != "" {
					status.Format = "v2-scrypt"
				} else {
					status.Format = "v2-raw-key"
				}
			}
		}
	}
	return status
}

// DeriveKEK reproduces the v1 SHA-256 key only for legacy-store migration.
func DeriveKEK(material []byte) []byte {
	sum := sha256.Sum256(material)
	out := make([]byte, kekBytes)
	copy(out, sum[:])
	return out
}

// ParseEnvKEK reproduces the v1 env-key format for legacy-store migration.
// New stores use resolveKEK, which salts passwords and uses random keys directly.
func ParseEnvKEK(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, fmt.Errorf("secrets: empty %s", EnvKEK)
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil && len(b) >= 16 {
		return DeriveKEK(b), nil
	}
	if b, err := hex.DecodeString(v); err == nil && len(b) >= 16 {
		return DeriveKEK(b), nil
	}
	return DeriveKEK([]byte(v)), nil
}

// decodeRawKEK accepts only exactly 32 decoded bytes. Unlike a password, this
// random key is used directly and is never sent through a password KDF.
func decodeRawKEK(v string) ([]byte, bool) {
	for _, decode := range []func(string) ([]byte, error){base64.StdEncoding.DecodeString, hex.DecodeString} {
		if b, err := decode(v); err == nil && len(b) == kekBytes {
			return b, true
		}
	}
	return nil, false
}

// Warning returns an operator-facing hint when KEK is not pinned via env.
func (s Status) Warning() string {
	switch s.Source {
	case SourceEnv:
		return ""
	case SourceFile:
		return fmt.Sprintf("secrets KEK is file-backed (%s); set %s so recreating the data volume without the file still decrypts", s.Path, EnvKEK)
	default:
		return fmt.Sprintf("secrets KEK not pinned; set %s (or rely on persistent %s in the gateway data volume)", EnvKEK, FileKEK)
	}
}

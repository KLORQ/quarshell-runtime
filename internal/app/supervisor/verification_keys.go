package supervisor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

const maximumGatewayVerificationKeyBytes = 64 << 10

type gatewayVerificationKey struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// validateGatewayVerificationKeyFile consumes the immutable key bundle
// delivered by the VM driver before the guest supervisor starts workload
// code. The file must share the protected directory used by supervisor mTLS.
func validateGatewayVerificationKeyFile(path, gatewayID, privateDir string) error {
	_, err := loadGatewayVerificationKeys(path, gatewayID, privateDir)
	return err
}

func loadGatewayVerificationKeys(path, gatewayID, privateDir string) (map[string]ed25519.PublicKey, error) {
	if path == "" && gatewayID == "" {
		return nil, nil
	}
	if path == "" || gatewayID == "" || strings.TrimSpace(gatewayID) != gatewayID || strings.IndexFunc(gatewayID, unicode.IsSpace) >= 0 {
		return nil, fmt.Errorf("Gateway identity and verification keys must be configured together")
	}
	if privateDir == "" || !filepath.IsAbs(privateDir) || filepath.Clean(privateDir) != privateDir {
		return nil, fmt.Errorf("verification keys require the private supervisor control directory")
	}
	expected := filepath.Join(privateDir, "gateway-verification-keys.json")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path != expected {
		return nil, fmt.Errorf("verification key path is outside the private supervisor control directory")
	}
	directoryInfo, err := os.Lstat(privateDir)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("supervisor control directory must be a private real directory")
	}
	if !ownedByEffectiveIdentity(directoryInfo) {
		return nil, fmt.Errorf("supervisor control directory must be owned by the supervisor identity")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o600 || before.Size() <= 0 || before.Size() > maximumGatewayVerificationKeyBytes {
		return nil, fmt.Errorf("verification key file must be a non-empty regular mode-0600 file no larger than %d bytes", maximumGatewayVerificationKeyBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open verification key file: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("verification key file changed while being opened")
	}
	if !ownedByEffectiveIdentity(after) {
		return nil, fmt.Errorf("verification key file must be owned by the supervisor identity")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumGatewayVerificationKeyBytes+1))
	if err != nil || len(data) == 0 || len(data) > maximumGatewayVerificationKeyBytes {
		return nil, fmt.Errorf("read verification key file: invalid size or read failure")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var records []json.RawMessage
	if err := decoder.Decode(&records); err != nil {
		return nil, fmt.Errorf("decode verification key set: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("verification key set contains trailing data")
	}
	if len(records) == 0 || len(records) > 32 {
		return nil, fmt.Errorf("verification key set must contain between 1 and 32 keys")
	}
	keys := make(map[string]ed25519.PublicKey, len(records))
	for index, record := range records {
		key, err := decodeGatewayVerificationKey(record)
		if err != nil {
			return nil, fmt.Errorf("verification key %d: %w", index, err)
		}
		if key.KeyID == "" || strings.TrimSpace(key.KeyID) != key.KeyID || strings.IndexFunc(key.KeyID, unicode.IsSpace) >= 0 {
			return nil, fmt.Errorf("verification key %d has an invalid key ID", index)
		}
		if _, duplicate := keys[key.KeyID]; duplicate {
			return nil, fmt.Errorf("verification key set repeats key ID %q", key.KeyID)
		}
		block, rest := pem.Decode([]byte(key.PublicKeyPEM))
		if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("verification key %q is not one PUBLIC KEY PEM block", key.KeyID)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		publicKey, ok := parsed.(ed25519.PublicKey)
		if err != nil || !ok || len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("verification key %q is not an Ed25519 public key", key.KeyID)
		}
		keys[key.KeyID] = bytes.Clone(publicKey)
	}
	return keys, nil
}

func decodeGatewayVerificationKey(raw []byte) (gatewayVerificationKey, error) {
	var key gatewayVerificationKey
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return key, fmt.Errorf("expected a JSON object")
	}
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return key, fmt.Errorf("read field name: %w", err)
		}
		name, ok := token.(string)
		if !ok {
			return key, fmt.Errorf("invalid field name")
		}
		if _, duplicate := seen[name]; duplicate {
			return key, fmt.Errorf("repeats field %q", name)
		}
		seen[name] = struct{}{}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return key, fmt.Errorf("field %q must be a string", name)
		}
		switch name {
		case "key_id":
			key.KeyID = value
		case "public_key_pem":
			key.PublicKeyPEM = value
		default:
			return key, fmt.Errorf("unknown field %q", name)
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return key, fmt.Errorf("JSON object is not closed")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return key, fmt.Errorf("contains trailing data")
	}
	if len(seen) != 2 || key.KeyID == "" || key.PublicKeyPEM == "" {
		return key, fmt.Errorf("requires key_id and public_key_pem")
	}
	return key, nil
}

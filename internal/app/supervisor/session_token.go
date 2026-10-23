package supervisor

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	sandboxSessionTokenType = "openshell-sandbox-session+jwt"
	sandboxSessionAudience  = "openshell-sandbox"
	sessionTokenClockLeeway = 30 * time.Second
	sessionTokenMaxLifetime = time.Hour
	maxSessionTokenBytes    = 64 << 10
)

type sandboxSessionJWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

type sandboxSessionJWTClaims struct {
	Issuer            string `json:"iss"`
	Subject           string `json:"sub"`
	Audience          string `json:"aud"`
	IssuedAt          int64  `json:"iat"`
	ExpiresAt         int64  `json:"exp"`
	TokenID           string `json:"jti"`
	SandboxID         string `json:"sandbox_id"`
	RuntimeGeneration string `json:"runtime_generation"`
	AuthEpoch         uint64 `json:"auth_epoch"`
	Component         string `json:"component"`
}

// verifyGatewaySandboxToken verifies the exact OpenShell Sandbox Protocol
// session profile before the guest supervisor opens its relay session.
func verifyGatewaySandboxToken(token, gatewayID, sandboxID, generation, epochValue, keysPath, privateDir string, now time.Time) error {
	if strings.TrimSpace(token) == "" || len(token) > maxSessionTokenBytes {
		return fmt.Errorf("sandbox session token is missing or exceeds the size limit")
	}
	epoch, err := strconv.ParseUint(epochValue, 10, 64)
	if err != nil || epoch == 0 || epochValue == "" {
		return fmt.Errorf("sandbox session credential epoch is invalid")
	}
	if !validSessionRuntimeGeneration(generation) || sandboxID == "" || strings.TrimSpace(sandboxID) != sandboxID {
		return fmt.Errorf("sandbox session runtime identity is invalid")
	}
	keys, err := loadGatewayVerificationKeys(keysPath, gatewayID, privateDir)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("sandbox session verification keys are not configured")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("sandbox session token encoding is invalid")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("sandbox session token header encoding is invalid")
	}
	var header sandboxSessionJWTHeader
	if err := decodeStrictSessionJSON(headerBytes, &header); err != nil || header.Algorithm != "EdDSA" || header.Type != sandboxSessionTokenType || header.KeyID == "" {
		return fmt.Errorf("sandbox session token header profile is invalid")
	}
	publicKey := keys[header.KeyID]
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("sandbox session token key ID is unknown")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return fmt.Errorf("sandbox session token signature is invalid")
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("sandbox session token claims encoding is invalid")
	}
	var claims sandboxSessionJWTClaims
	if err := decodeStrictSessionJSON(claimsBytes, &claims); err != nil {
		return fmt.Errorf("sandbox session token claims are invalid")
	}
	var claimFields map[string]json.RawMessage
	if err := json.Unmarshal(claimsBytes, &claimFields); err != nil || claimFields["exp"] == nil {
		return fmt.Errorf("sandbox session token is missing its expiry claim")
	}
	if claimFields["iat"] == nil {
		return fmt.Errorf("sandbox session token is missing its issued-at claim")
	}
	var issuedAtClaim *int64
	if err := json.Unmarshal(claimFields["iat"], &issuedAtClaim); err != nil || issuedAtClaim == nil || *issuedAtClaim != claims.IssuedAt {
		return fmt.Errorf("sandbox session token issued-at claim is not an integer")
	}
	var expiryClaim *int64
	if err := json.Unmarshal(claimFields["exp"], &expiryClaim); err != nil || expiryClaim == nil || *expiryClaim != claims.ExpiresAt {
		return fmt.Errorf("sandbox session token expiry claim is not an integer")
	}
	if claims.Issuer != "openshell-gateway:"+gatewayID || claims.Subject != "spiffe://openshell/sandbox/"+sandboxID || claims.Audience != sandboxSessionAudience || claims.Component != "openshell-supervisor" || claims.SandboxID != sandboxID || claims.RuntimeGeneration != generation || claims.AuthEpoch != epoch || !validSessionTokenID(claims.TokenID) {
		return fmt.Errorf("sandbox session token claims do not match the active VM session (issuer=%t subject=%t audience=%t component=%t sandbox=%t generation=%t epoch=%t token_id=%t)", claims.Issuer == "openshell-gateway:"+gatewayID, claims.Subject == "spiffe://openshell/sandbox/"+sandboxID, claims.Audience == sandboxSessionAudience, claims.Component == "openshell-supervisor", claims.SandboxID == sandboxID, claims.RuntimeGeneration == generation, claims.AuthEpoch == epoch, validSessionTokenID(claims.TokenID))
	}
	if claims.IssuedAt > now.Unix()+int64(sessionTokenClockLeeway.Seconds()) {
		return fmt.Errorf("sandbox session token was issued in the future")
	}
	if claims.ExpiresAt != 0 {
		if claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > int64(sessionTokenMaxLifetime.Seconds()) || claims.ExpiresAt < now.Unix()-int64(sessionTokenClockLeeway.Seconds()) {
			return fmt.Errorf("sandbox session token lifetime is invalid or expired")
		}
	}
	return nil
}

func validSessionRuntimeGeneration(value string) bool {
	if len(value) != 17 || value[0] != 'g' {
		return false
	}
	for _, char := range value[1:] {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func validSessionTokenID(value string) bool {
	if len(value) != 36 || strings.ToLower(value) != value || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func decodeStrictSessionJSON(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maxSessionTokenBytes {
		return fmt.Errorf("JSON value has an invalid size")
	}
	duplicateCheck := json.NewDecoder(bytes.NewReader(raw))
	if err := scanSessionJSONValue(duplicateCheck); err != nil {
		return err
	}
	if _, err := duplicateCheck.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("JSON value has trailing data")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("JSON value has trailing data")
	}
	return nil
}

func scanSessionJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return fmt.Errorf("JSON object field name is invalid")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("JSON object repeats field %q", name)
			}
			seen[name] = struct{}{}
			if err := scanSessionJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanSessionJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("JSON array is not closed")
		}
	default:
		return fmt.Errorf("JSON value has an unexpected delimiter")
	}
	return nil
}

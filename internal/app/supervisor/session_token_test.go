//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package supervisor

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyGatewaySandboxToken(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	privateDir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keysPath := filepath.Join(privateDir, "gateway-verification-keys.json")
	encodedKeys, _ := json.Marshal([]gatewayVerificationKey{{KeyID: "session-v1", PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}})
	if err := os.WriteFile(keysPath, encodedKeys, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	tokenIDBytes := make([]byte, 16)
	if _, err := rand.Read(tokenIDBytes); err != nil {
		t.Fatal(err)
	}
	tokenIDBytes[6] = (tokenIDBytes[6] & 0x0f) | 0x40
	tokenIDBytes[8] = (tokenIDBytes[8] & 0x3f) | 0x80
	tokenID := fmt.Sprintf("%x-%x-%x-%x-%x", tokenIDBytes[:4], tokenIDBytes[4:6], tokenIDBytes[6:8], tokenIDBytes[8:10], tokenIDBytes[10:])
	baseHeader := sandboxSessionJWTHeader{Algorithm: "EdDSA", Type: sandboxSessionTokenType, KeyID: "session-v1"}
	baseClaims := sandboxSessionJWTClaims{Issuer: "openshell-gateway:gw-a", Subject: "spiffe://openshell/sandbox/sb-a", Audience: sandboxSessionAudience, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), TokenID: tokenID, SandboxID: "sb-a", RuntimeGeneration: "g0000000000000001", AuthEpoch: 2, Component: "openshell-supervisor"}
	sign := func(header sandboxSessionJWTHeader, claims sandboxSessionJWTClaims) string {
		headerBytes, _ := json.Marshal(header)
		claimsBytes, _ := json.Marshal(claims)
		return signSessionJWT(private, headerBytes, claimsBytes)
	}
	token := sign(baseHeader, baseClaims)
	args := []string{token, "gw-a", "sb-a", "g0000000000000001", "2", keysPath, privateDir}
	if err := verifyGatewaySandboxToken(args[0], args[1], args[2], args[3], args[4], args[5], args[6], now); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if err := verifyGatewaySandboxToken(args[0], args[1], "sb-other", args[3], args[4], args[5], args[6], now); err == nil {
		t.Fatal("token for another sandbox accepted")
	}
	if err := verifyGatewaySandboxToken(args[0], args[1], args[2], args[3], "3", args[5], args[6], now); err == nil {
		t.Fatal("token from another auth epoch accepted")
	}
	if err := verifyGatewaySandboxToken(args[0]+"x", args[1], args[2], args[3], args[4], args[5], args[6], now); err == nil {
		t.Fatal("invalid signature accepted")
	}
	for _, test := range []struct {
		name   string
		header sandboxSessionJWTHeader
		claims sandboxSessionJWTClaims
	}{
		{name: "wrong JOSE type", header: sandboxSessionJWTHeader{Algorithm: "EdDSA", Type: "JWT", KeyID: "session-v1"}, claims: baseClaims},
		{name: "wrong algorithm", header: sandboxSessionJWTHeader{Algorithm: "none", Type: sandboxSessionTokenType, KeyID: "session-v1"}, claims: baseClaims},
		{name: "expired", header: baseHeader, claims: func() sandboxSessionJWTClaims { c := baseClaims; c.ExpiresAt = now.Add(-time.Minute).Unix(); return c }()},
		{name: "issued too far in future", header: baseHeader, claims: func() sandboxSessionJWTClaims { c := baseClaims; c.IssuedAt = now.Add(time.Minute).Unix(); return c }()},
		{name: "wrong component", header: baseHeader, claims: func() sandboxSessionJWTClaims { c := baseClaims; c.Component = "other"; return c }()},
	} {
		t.Run(test.name, func(t *testing.T) {
			badToken := sign(test.header, test.claims)
			if err := verifyGatewaySandboxToken(badToken, args[1], args[2], args[3], args[4], args[5], args[6], now); err == nil {
				t.Fatal("invalid session token accepted")
			}
		})
	}
	nonExpiringClaims := baseClaims
	nonExpiringClaims.ExpiresAt = 0
	if err := verifyGatewaySandboxToken(sign(baseHeader, nonExpiringClaims), args[1], args[2], args[3], args[4], args[5], args[6], now); err != nil {
		t.Fatalf("OpenShell non-expiring token rejected: %v", err)
	}
	headerBytes, _ := json.Marshal(baseHeader)
	duplicateClaims := []byte(`{"iss":"openshell-gateway:gw-a","iss":"shadow","sub":"spiffe://openshell/sandbox/sb-a","aud":"openshell-sandbox","iat":1800000000,"exp":1800000060,"jti":"` + tokenID + `","sandbox_id":"sb-a","runtime_generation":"g0000000000000001","auth_epoch":2,"component":"openshell-supervisor"}`)
	if err := verifyGatewaySandboxToken(signSessionJWT(private, headerBytes, duplicateClaims), args[1], args[2], args[3], args[4], args[5], args[6], now); err == nil {
		t.Fatal("duplicate claim accepted")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(claimsForTest(t, baseClaims), &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "exp")
	missingExpiry, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyGatewaySandboxToken(signSessionJWT(private, headerBytes, missingExpiry), args[1], args[2], args[3], args[4], args[5], args[6], now); err == nil {
		t.Fatal("token with omitted required exp claim accepted")
	}
	fields["exp"] = json.RawMessage("null")
	nullExpiry, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyGatewaySandboxToken(signSessionJWT(private, headerBytes, nullExpiry), args[1], args[2], args[3], args[4], args[5], args[6], now); err == nil {
		t.Fatal("token with null exp claim accepted as non-expiring")
	}
	fields["exp"] = json.RawMessage("1800000060")
	delete(fields, "iat")
	missingIssuedAt, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyGatewaySandboxToken(signSessionJWT(private, headerBytes, missingIssuedAt), args[1], args[2], args[3], args[4], args[5], args[6], now); err == nil {
		t.Fatal("token with omitted required iat claim accepted")
	}
	fields["iat"] = json.RawMessage("null")
	nullIssuedAt, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyGatewaySandboxToken(signSessionJWT(private, headerBytes, nullIssuedAt), args[1], args[2], args[3], args[4], args[5], args[6], now); err == nil {
		t.Fatal("token with null iat claim accepted")
	}
}

func claimsForTest(t *testing.T, claims sandboxSessionJWTClaims) []byte {
	t.Helper()
	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func signSessionJWT(private ed25519.PrivateKey, header, claims []byte) string {
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(unsigned)))
}

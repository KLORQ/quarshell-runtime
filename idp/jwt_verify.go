package idp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

func verifyJWTSignature(signingInput, sigB64 string, key jwkSigningKey) ([]byte, error) {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("oidc: signature encoding: %w", err)
	}
	var hash crypto.Hash
	var digest []byte
	switch key.Algorithm {
	case "RS256", "PS256", "ES256":
		sum := sha256.Sum256([]byte(signingInput))
		digest = sum[:]
		hash = crypto.SHA256
	case "RS384", "PS384", "ES384":
		sum := sha512.Sum384([]byte(signingInput))
		digest = sum[:]
		hash = crypto.SHA384
	case "RS512", "PS512":
		sum := sha512.Sum512([]byte(signingInput))
		digest = sum[:]
		hash = crypto.SHA512
	case "EdDSA":
		pub, ok := key.Key.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(pub, []byte(signingInput), sig) {
			return nil, fmt.Errorf("oidc: signature verification failed")
		}
	default:
		return nil, fmt.Errorf("oidc: unsupported signing algorithm %q", key.Algorithm)
	}
	switch pub := key.Key.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(key.Algorithm, "PS") {
			err = rsa.VerifyPSS(pub, hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash})
		} else {
			err = rsa.VerifyPKCS1v15(pub, hash, digest, sig)
		}
	case *ecdsa.PublicKey:
		width := 32
		if key.Algorithm == "ES384" {
			width = 48
		}
		if len(sig) != 2*width {
			return nil, fmt.Errorf("oidc: invalid ECDSA signature size")
		}
		der, marshalErr := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:width]), new(big.Int).SetBytes(sig[width:])})
		if marshalErr != nil {
			return nil, fmt.Errorf("oidc: invalid ECDSA signature")
		}
		if !ecdsa.VerifyASN1(pub, digest, der) {
			err = fmt.Errorf("invalid ECDSA signature")
		}
	case ed25519.PublicKey:
		// EdDSA was verified above.
	default:
		return nil, fmt.Errorf("oidc: unsupported public key type")
	}
	if err != nil {
		return nil, fmt.Errorf("oidc: signature verification failed: %w", err)
	}
	_, encodedPayload, _ := strings.Cut(signingInput, ".")
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, fmt.Errorf("oidc: payload decode: %w", err)
	}
	return payload, nil
}

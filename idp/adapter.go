// Package idp defines control-plane identity adapters (OIDC / mTLS).
package idp

// Claims is a minimal identity assertion after token validation.
type Claims struct {
	Subject string
	Issuer  string
	Email   string
	Raw     map[string]any
}

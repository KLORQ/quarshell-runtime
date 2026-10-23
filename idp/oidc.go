package idp

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDCConfig configures issuer-backed JWT validation (OpenShell-compatible subset).
type OIDCConfig struct {
	Issuer   string
	Audience string // optional aud claim
	// AllowInsecureHTTP permits http:// loopback issuers (local Dex/Keycloak).
	AllowInsecureHTTP bool
	// JWKSAllowedOrigins permits discovery documents to reference a JWKS on
	// explicitly trusted HTTPS origins other than the issuer origin.
	JWKSAllowedOrigins []string
	HTTPClient         *http.Client
	JWKSCacheTTL       time.Duration
}

// OIDC validates Bearer JWTs via issuer JWKS.
type OIDC struct {
	cfg     OIDCConfig
	mu      sync.Mutex
	keys    map[string]jwkSigningKey
	fetched time.Time
	jwksURI string
}

// NewOIDC builds a validator. Discovery runs lazily on first Validate.
func NewOIDC(cfg OIDCConfig) (*OIDC, error) {
	cfg.Issuer = strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: issuer required")
	}
	if err := validateIssuerURL(cfg.Issuer, cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	cfg.JWKSAllowedOrigins = append([]string(nil), cfg.JWKSAllowedOrigins...)
	for _, origin := range cfg.JWKSAllowedOrigins {
		if _, err := validateJWKSAllowedOrigin(origin, cfg.AllowInsecureHTTP); err != nil {
			return nil, err
		}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: oidcRequestTimeout}
	}
	client := *cfg.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg.HTTPClient = &client
	if cfg.JWKSCacheTTL <= 0 {
		cfg.JWKSCacheTTL = defaultJWKSCacheTTL
	}
	return &OIDC{cfg: cfg, keys: map[string]jwkSigningKey{}}, nil
}

// Issuer returns the configured issuer.
func (o *OIDC) Issuer() string { return o.cfg.Issuer }

// Validate verifies a JWT access/id token against JWKS.
func (o *OIDC) Validate(ctx context.Context, token string) (Claims, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Claims{}, fmt.Errorf("oidc: empty token")
	}
	if err := o.ensureKeys(ctx); err != nil {
		return Claims{}, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("oidc: malformed jwt")
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("oidc: header: %w", err)
	}
	var hdr struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return Claims{}, fmt.Errorf("oidc: header json: %w", err)
	}
	if !supportedJWTAlgorithm(hdr.Alg) {
		return Claims{}, fmt.Errorf("oidc: unsupported alg %q", hdr.Alg)
	}
	if hdr.Typ != "" && hdr.Typ != "JWT" {
		return Claims{}, fmt.Errorf("oidc: unsupported typ %q (want JWT)", hdr.Typ)
	}
	o.mu.Lock()
	key, found := o.keys[hdr.Kid]
	o.mu.Unlock()
	if !found {
		// force refresh once for unknown kid
		o.mu.Lock()
		o.fetched = time.Time{}
		o.mu.Unlock()
		if err := o.ensureKeys(ctx); err != nil {
			return Claims{}, err
		}
		o.mu.Lock()
		key, found = o.keys[hdr.Kid]
		o.mu.Unlock()
		if !found {
			return Claims{}, fmt.Errorf("oidc: unknown kid %q", hdr.Kid)
		}
	}
	if hdr.Alg != key.Algorithm {
		return Claims{}, fmt.Errorf("oidc: token algorithm does not match signing key")
	}
	payload, err := verifyJWTSignature(parts[0]+"."+parts[1], parts[2], key)
	if err != nil {
		return Claims{}, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, fmt.Errorf("oidc: claims: %w", err)
	}
	iss, _ := claims["iss"].(string)
	if strings.TrimRight(iss, "/") != o.cfg.Issuer {
		return Claims{}, fmt.Errorf("oidc: issuer mismatch")
	}
	if _, present := claims["exp"]; !present {
		return Claims{}, fmt.Errorf("oidc: exp claim required")
	}
	if sub, _ := claims["sub"].(string); strings.TrimSpace(sub) == "" {
		return Claims{}, fmt.Errorf("oidc: sub claim required")
	}
	if o.cfg.Audience != "" {
		if !audienceOK(claims["aud"], o.cfg.Audience) {
			return Claims{}, fmt.Errorf("oidc: audience mismatch")
		}
	} else if _, supplied := claims["aud"]; supplied {
		slog.Warn("oidc audience not configured; token audience is unchecked")
	}
	if err := validateTokenTimes(claims, time.Now()); err != nil {
		return Claims{}, err
	}
	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	return Claims{Subject: sub, Issuer: iss, Email: email, Raw: claims}, nil
}

const tokenClockLeeway = 90 * time.Second

func validateTokenTimes(claims map[string]any, now time.Time) error {
	for _, field := range []string{"exp", "nbf", "iat"} {
		value, exists := claims[field]
		if !exists {
			continue
		}
		instant, ok := numericTime(value)
		if !ok {
			return fmt.Errorf("oidc: invalid %s claim", field)
		}
		switch field {
		case "exp":
			if now.After(instant.Add(tokenClockLeeway)) {
				return fmt.Errorf("oidc: token expired")
			}
		case "nbf", "iat":
			if now.Add(tokenClockLeeway).Before(instant) {
				return fmt.Errorf("oidc: token %s is in the future", field)
			}
		}
	}
	return nil
}

func (o *OIDC) ensureKeys(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.keys) > 0 && time.Since(o.fetched) < o.cfg.JWKSCacheTTL {
		return nil
	}
	jwksURI := o.jwksURI
	if jwksURI == "" {
		disc, err := Discover(ctx, o.cfg.Issuer, o.cfg.HTTPClient)
		if err != nil {
			return err
		}
		jwksURI = disc.JWKSURI
		if err := validateJWKSURL(jwksURI, o.cfg); err != nil {
			return err
		}
		o.jwksURI = jwksURI
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return err
	}
	res, err := o.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("oidc jwks: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		return fmt.Errorf("oidc jwks: %s", res.Status)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("oidc jwks parse: %w", err)
	}
	keys := map[string]jwkSigningKey{}
	poisoned := map[string]bool{}
	for _, k := range doc.Keys {
		key, err := jwkToSigningKey(k)
		if err != nil {
			continue
		}
		kid := k.Kid
		if kid == "" {
			continue
		}
		if poisoned[kid] {
			continue
		}
		if old, exists := keys[kid]; exists && old.Algorithm != key.Algorithm {
			delete(keys, kid)
			poisoned[kid] = true
			continue
		}
		keys[kid] = key
	}
	if len(keys) == 0 {
		return fmt.Errorf("oidc jwks: no usable signing keys")
	}
	o.keys = keys
	o.fetched = time.Now()
	return nil
}

// Discovery is the OpenID provider metadata subset we need.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	DeviceAuthEndpoint    string `json:"device_authorization_endpoint"`
}

// Discover fetches /.well-known/openid-configuration.
func Discover(ctx context.Context, issuer string, client *http.Client) (Discovery, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if client == nil {
		client = &http.Client{Timeout: oidcRequestTimeout}
	}
	url := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Discovery{}, err
	}
	res, err := client.Do(req)
	if err != nil {
		return Discovery{}, fmt.Errorf("oidc discovery: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return Discovery{}, err
	}
	if res.StatusCode >= 300 {
		return Discovery{}, fmt.Errorf("oidc discovery: %s", res.Status)
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return Discovery{}, err
	}
	if strings.TrimRight(d.Issuer, "/") != issuer {
		return Discovery{}, fmt.Errorf("oidc discovery issuer mismatch: want %s got %s", issuer, d.Issuer)
	}
	return d, nil
}

type jwk struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	Alg    string   `json:"alg"`
	Use    string   `json:"use"`
	KeyOps []string `json:"key_ops"`
}

type jwkSigningKey struct {
	Key       crypto.PublicKey
	Algorithm string
}

func jwkToSigningKey(k jwk) (jwkSigningKey, error) {
	if k.Use != "" && k.Use != "sig" {
		return jwkSigningKey{}, fmt.Errorf("unsupported JWK use")
	}
	if len(k.KeyOps) > 0 && !containsJWKOperation(k.KeyOps, "verify") {
		return jwkSigningKey{}, fmt.Errorf("JWK is not permitted for verification")
	}
	var key crypto.PublicKey
	algorithm := k.Alg
	switch k.Kty {
	case "RSA":
		if k.N == "" || k.E == "" {
			return jwkSigningKey{}, fmt.Errorf("RSA JWK missing components")
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return jwkSigningKey{}, err
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return jwkSigningKey{}, err
		}
		var exponent int
		for _, b := range eb {
			exponent = exponent<<8 + int(b)
		}
		if exponent < 3 || exponent%2 == 0 {
			return jwkSigningKey{}, fmt.Errorf("invalid RSA exponent")
		}
		key = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: exponent}
		if algorithm == "" {
			algorithm = "RS256"
		}
		if !isRSAJWTAlgorithm(algorithm) {
			return jwkSigningKey{}, fmt.Errorf("RSA JWK algorithm mismatch")
		}
	case "EC":
		var curve ecdh.Curve
		var curveOID asn1.ObjectIdentifier
		switch k.Crv {
		case "P-256":
			curve, curveOID, algorithm = ecdh.P256(), asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}, defaultIfEmpty(algorithm, "ES256")
		case "P-384":
			curve, curveOID, algorithm = ecdh.P384(), asn1.ObjectIdentifier{1, 3, 132, 0, 34}, defaultIfEmpty(algorithm, "ES384")
		default:
			return jwkSigningKey{}, fmt.Errorf("unsupported EC curve")
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return jwkSigningKey{}, err
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return jwkSigningKey{}, err
		}
		point := make([]byte, 1, 1+len(xb)+len(yb))
		point[0] = 4
		point = append(point, xb...)
		point = append(point, yb...)
		if _, err := curve.NewPublicKey(point); err != nil {
			return jwkSigningKey{}, fmt.Errorf("EC point is invalid: %w", err)
		}
		parameters, err := asn1.Marshal(curveOID)
		if err != nil {
			return jwkSigningKey{}, err
		}
		info := struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, Parameters: asn1.RawValue{FullBytes: parameters}}, asn1.BitString{Bytes: point, BitLength: len(point) * 8}}
		der, err := asn1.Marshal(info)
		if err != nil {
			return jwkSigningKey{}, err
		}
		key, err = x509.ParsePKIXPublicKey(der)
		if err != nil {
			return jwkSigningKey{}, err
		}
	case "OKP":
		if k.Crv != "Ed25519" {
			return jwkSigningKey{}, fmt.Errorf("unsupported OKP curve")
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return jwkSigningKey{}, err
		}
		if len(xb) != ed25519.PublicKeySize {
			return jwkSigningKey{}, fmt.Errorf("invalid Ed25519 key size")
		}
		key = ed25519.PublicKey(xb)
		algorithm = defaultIfEmpty(algorithm, "EdDSA")
	default:
		return jwkSigningKey{}, fmt.Errorf("unsupported JWK key type")
	}
	if k.Alg != "" && k.Alg != algorithm {
		return jwkSigningKey{}, fmt.Errorf("JWK algorithm does not match key type")
	}
	if !supportedJWTAlgorithm(algorithm) {
		return jwkSigningKey{}, fmt.Errorf("unsupported JWT signing algorithm")
	}
	return jwkSigningKey{Key: key, Algorithm: algorithm}, nil
}

func containsJWKOperation(ops []string, wanted string) bool {
	for _, op := range ops {
		if op == wanted {
			return true
		}
	}
	return false
}
func defaultIfEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
func isRSAJWTAlgorithm(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return true
	}
	return false
}
func supportedJWTAlgorithm(alg string) bool {
	return isRSAJWTAlgorithm(alg) || alg == "ES256" || alg == "ES384" || alg == "EdDSA"
}

func audienceOK(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func numericTime(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(i, 0), true
	default:
		return time.Time{}, false
	}
}

func validateIssuerURL(issuer string, allowHTTP bool) error {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return fmt.Errorf("oidc: issuer must be an absolute URL with a host and no credentials")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(issuer, "#") {
		return fmt.Errorf("oidc: issuer must not include a query or fragment")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if allowHTTP && numericLoopback(parsed.Hostname()) {
			return nil
		}
		if allowHTTP {
			return fmt.Errorf("oidc: insecure HTTP is allowed only for numeric loopback issuers")
		}
		return fmt.Errorf("oidc: issuer must use HTTPS (numeric-loopback HTTP requires AllowInsecureHTTP)")
	default:
		return fmt.Errorf("oidc: issuer must use HTTPS")
	}
}

func validateJWKSAllowedOrigin(value string, allowHTTP bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return nil, fmt.Errorf("oidc: JWKS allowed origin must be an absolute URL with a host and no credentials")
	}
	if parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(value, "#") {
		return nil, fmt.Errorf("oidc: JWKS allowed origin must not include a path, query, or fragment")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && (scheme != "http" || !allowHTTP || !numericLoopback(parsed.Hostname())) {
		return nil, fmt.Errorf("oidc: JWKS allowed origin must use HTTPS")
	}
	return parsed, nil
}

func validateJWKSURL(value string, config OIDCConfig) error {
	jwks, err := url.Parse(strings.TrimSpace(value))
	if err != nil || jwks.Hostname() == "" || jwks.User != nil {
		return fmt.Errorf("oidc: discovery jwks_uri must be an absolute URL with a host and no credentials")
	}
	if strings.Contains(value, "#") {
		return fmt.Errorf("oidc: discovery jwks_uri must not include a fragment")
	}
	scheme := strings.ToLower(jwks.Scheme)
	if scheme != "https" && (scheme != "http" || !config.AllowInsecureHTTP || !numericLoopback(jwks.Hostname())) {
		return fmt.Errorf("oidc: discovery jwks_uri must use HTTPS")
	}
	issuer, _ := url.Parse(config.Issuer)
	if sameURLOrigin(jwks, issuer) {
		return nil
	}
	for _, value := range config.JWKSAllowedOrigins {
		allowed, err := validateJWKSAllowedOrigin(value, config.AllowInsecureHTTP)
		if err == nil && sameURLOrigin(jwks, allowed) {
			return nil
		}
	}
	return fmt.Errorf("oidc: discovery jwks_uri origin %q does not match issuer origin %q; configure jwks_allowed_origins only for a trusted origin", urlOrigin(jwks), urlOrigin(issuer))
}

func sameURLOrigin(left, right *url.URL) bool { return urlOrigin(left) == urlOrigin(right) }

func urlOrigin(value *url.URL) string {
	if value == nil {
		return ""
	}
	scheme := strings.ToLower(value.Scheme)
	host := strings.ToLower(value.Hostname())
	port := value.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

func numericLoopback(host string) bool {
	address, err := netip.ParseAddr(host)
	return err == nil && address.Zone() == "" && address.Unmap().IsLoopback()
}

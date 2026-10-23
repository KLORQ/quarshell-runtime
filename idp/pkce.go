package idp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenBundle is the result of an interactive or refresh OIDC login.
type TokenBundle struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresIn    int64
	Expiry       time.Time
}

// PKCEConfig drives Authorization Code + PKCE (OpenShell gateway login).
type PKCEConfig struct {
	Issuer            string
	ClientID          string
	ClientSecret      string // optional (public clients leave empty)
	Audience          string
	Scopes            string // space-separated; openid always included
	AllowInsecureHTTP bool
	OpenURL           func(string) error // optional browser opener
	HTTPClient        *http.Client
	Timeout           time.Duration
	// RedirectPort when >0 binds 127.0.0.1:RedirectPort (needed for Dex static redirectURIs).
	RedirectPort int
}

// AuthorizationRequest contains short-lived state required to finish an
// Authorization Code + PKCE exchange. Keep it on the trusted server side.
type AuthorizationRequest struct {
	URL           string
	State         string
	Verifier      string
	RedirectURI   string
	TokenEndpoint string
}

// PrepareAuthorization creates an authorization URL for a caller-owned HTTP
// callback. This lets browser-facing services share the same PKCE behavior as
// BrowserPKCE without exposing the verifier to the browser.
func PrepareAuthorization(ctx context.Context, cfg PKCEConfig, redirectURI string) (AuthorizationRequest, error) {
	if strings.TrimSpace(cfg.ClientID) == "" {
		return AuthorizationRequest{}, fmt.Errorf("oidc pkce: client_id required")
	}
	cfg.Issuer = strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	if err := validateIssuerURL(cfg.Issuer, cfg.AllowInsecureHTTP); err != nil {
		return AuthorizationRequest{}, err
	}
	redirect, err := url.Parse(redirectURI)
	redirectSchemeAllowed := err == nil && (redirect.Scheme == "https" || redirect.Scheme == "http" && isLoopbackRedirectHost(redirect.Hostname()))
	if err != nil || redirect.Host == "" || redirect.User != nil || redirect.Fragment != "" || !redirectSchemeAllowed {
		return AuthorizationRequest{}, fmt.Errorf("oidc pkce: redirect URI must use https or loopback http")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: oauthRequestTimeout}
	}
	disc, err := Discover(ctx, cfg.Issuer, cfg.HTTPClient)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	if err := validateOAuthEndpoint(disc.AuthorizationEndpoint, cfg.AllowInsecureHTTP); err != nil {
		return AuthorizationRequest{}, fmt.Errorf("oidc authorization endpoint: %w", err)
	}
	if err := validateOAuthEndpoint(disc.TokenEndpoint, cfg.AllowInsecureHTTP); err != nil {
		return AuthorizationRequest{}, fmt.Errorf("oidc token endpoint: %w", err)
	}
	verifier, challenge, err := newPKCE()
	if err != nil {
		return AuthorizationRequest{}, err
	}
	state, err := randomURLString(16)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	q := authorizationValues(cfg, redirectURI, state, challenge)
	return AuthorizationRequest{
		URL: disc.AuthorizationEndpoint + "?" + q.Encode(), State: state,
		Verifier: verifier, RedirectURI: redirectURI, TokenEndpoint: disc.TokenEndpoint,
	}, nil
}

func validateOAuthEndpoint(raw string, allowInsecureHTTP bool) error {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return fmt.Errorf("invalid URL")
	}
	if endpoint.Scheme == "https" {
		return nil
	}
	if endpoint.Scheme == "http" && allowInsecureHTTP && isLoopbackRedirectHost(endpoint.Hostname()) {
		return nil
	}
	return fmt.Errorf("must use https (or explicitly allowed loopback http)")
}

// ExchangeAuthorizationCode completes a request returned by
// PrepareAuthorization after the caller has verified its state and browser
// binding.
func ExchangeAuthorizationCode(ctx context.Context, cfg PKCEConfig, prepared AuthorizationRequest, code string) (TokenBundle, error) {
	if strings.TrimSpace(code) == "" || prepared.TokenEndpoint == "" || prepared.RedirectURI == "" || prepared.Verifier == "" {
		return TokenBundle{}, fmt.Errorf("oidc pkce: incomplete authorization callback")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: oauthRequestTimeout}
	}
	return exchangeCode(ctx, cfg, prepared.TokenEndpoint, code, prepared.RedirectURI, prepared.Verifier)
}

// BrowserPKCE runs Authorization Code + PKCE against the issuer.
func BrowserPKCE(ctx context.Context, cfg PKCEConfig) (TokenBundle, error) {
	if strings.TrimSpace(cfg.ClientID) == "" {
		return TokenBundle{}, fmt.Errorf("oidc pkce: client_id required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: oauthRequestTimeout}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultLoginTimeout
	}
	listenAddr := "127.0.0.1:0"
	if cfg.RedirectPort > 0 {
		listenAddr = fmt.Sprintf("127.0.0.1:%d", cfg.RedirectPort)
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return TokenBundle{}, err
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	prepared, err := PrepareAuthorization(ctx, cfg, redirectURI)
	if err != nil {
		return TokenBundle{}, err
	}

	type result struct {
		code string
		err  error
	}
	ch := make(chan result, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}
			if r.URL.Query().Get("state") != prepared.State {
				http.Error(w, "state mismatch", http.StatusBadRequest)
				ch <- result{err: fmt.Errorf("oidc: state mismatch")}
				return
			}
			if errMsg := r.URL.Query().Get("error"); errMsg != "" {
				desc := r.URL.Query().Get("error_description")
				http.Error(w, errMsg, http.StatusBadRequest)
				ch <- result{err: fmt.Errorf("oidc: %s (%s)", errMsg, desc)}
				return
			}
			code := r.URL.Query().Get("code")
			if code == "" {
				http.Error(w, "missing code", http.StatusBadRequest)
				ch <- result{err: fmt.Errorf("oidc: missing code")}
				return
			}
			fmt.Fprint(w, "cautem OIDC login ok — you can close this tab")
			ch <- result{code: code}
		}),
		ReadHeaderTimeout: callbackHeaderReadTimeout,
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shCtx, cancel := context.WithTimeout(context.Background(), callbackShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shCtx)
	}()

	if cfg.OpenURL != nil {
		_ = cfg.OpenURL(prepared.URL)
	}

	var code string
	select {
	case <-ctx.Done():
		return TokenBundle{}, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return TokenBundle{}, res.err
		}
		code = res.code
	case <-time.After(cfg.Timeout):
		return TokenBundle{}, fmt.Errorf("oidc: timed out waiting for browser callback")
	}

	return ExchangeAuthorizationCode(ctx, cfg, prepared, code)
}

func authorizationValues(cfg PKCEConfig, redirectURI, state, challenge string) url.Values {
	var scopes strings.Builder
	scopes.WriteString("openid")
	for scope := range strings.FieldsSeq(strings.TrimSpace(cfg.Scopes)) {
		if scope != "openid" {
			scopes.WriteString(" " + scope)
		}
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scopes.String()},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if cfg.Audience != "" {
		q.Set("audience", cfg.Audience)
	}
	return q
}

func isLoopbackRedirectHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// RefreshTokens exchanges a refresh_token at the issuer token endpoint.
func RefreshTokens(ctx context.Context, cfg PKCEConfig, refreshToken string) (TokenBundle, error) {
	if refreshToken == "" {
		return TokenBundle{}, fmt.Errorf("oidc: empty refresh_token")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: oauthRequestTimeout}
	}
	disc, err := Discover(ctx, cfg.Issuer, cfg.HTTPClient)
	if err != nil {
		return TokenBundle{}, err
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", cfg.ClientID)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	return postToken(ctx, cfg.HTTPClient, disc.TokenEndpoint, form)
}

func exchangeCode(ctx context.Context, cfg PKCEConfig, tokenURL, code, redirectURI, verifier string) (TokenBundle, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", cfg.ClientID)
	form.Set("code_verifier", verifier)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	return postToken(ctx, cfg.HTTPClient, tokenURL, form)
}

func postToken(ctx context.Context, client *http.Client, tokenURL string, form url.Values) (TokenBundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenBundle{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return TokenBundle{}, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return TokenBundle{}, fmt.Errorf("oidc token: %s: %s", res.Status, strings.TrimSpace(string(body)))
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return TokenBundle{}, err
	}
	if tok.AccessToken == "" {
		return TokenBundle{}, fmt.Errorf("oidc token: empty access_token")
	}
	b := TokenBundle{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      tok.IDToken,
		TokenType:    tok.TokenType,
		ExpiresIn:    tok.ExpiresIn,
	}
	if tok.ExpiresIn > 0 {
		b.Expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return b, nil
}

func newPKCE() (verifier, challenge string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

func randomURLString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

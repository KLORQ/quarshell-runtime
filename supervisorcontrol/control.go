// Package supervisorcontrol provides a private lifecycle bridge between the
// sandbox PID 1 and its authenticated supervisor client.
package supervisorcontrol

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	OperationBegin            = "begin"
	OperationReport           = "report_main_process_exit"
	OperationFinalize         = "finalize_main_process_exit"
	OperationProcess          = "process_event"
	OperationFlush            = "flush_process_events"
	maxMessageBytes           = 8 << 10
	EnvSocket                 = "CAUTEM_SUPERVISOR_CONTROL_SOCKET"
	EnvEndpoint               = "CAUTEM_SUPERVISOR_CONTROL_ENDPOINT"
	EnvListen                 = "CAUTEM_SUPERVISOR_CONTROL_LISTEN"
	EnvClientCA               = "CAUTEM_SUPERVISOR_CONTROL_CLIENT_CA"
	EnvClientCert             = "CAUTEM_SUPERVISOR_CONTROL_CLIENT_CERT"
	EnvClientKey              = "CAUTEM_SUPERVISOR_CONTROL_CLIENT_KEY"
	EnvPrivateDir             = "CAUTEM_SUPERVISOR_CONTROL_PRIVATE_DIR"
	EnvServerCA               = "CAUTEM_SUPERVISOR_CONTROL_SERVER_CA"
	EnvServerCert             = "CAUTEM_SUPERVISOR_CONTROL_SERVER_CERT"
	EnvServerKey              = "CAUTEM_SUPERVISOR_CONTROL_SERVER_KEY"
	EnvExpectedClientIdentity = "CAUTEM_SUPERVISOR_CONTROL_EXPECTED_CLIENT_IDENTITY"
	unixServerName            = "cautem-supervisor-control"
	VMControlProtocol         = uint32(2)
	peerClaimsClockSkew       = 60 * time.Second
	maxPeerClaimNonces        = 16384
)

//go:embed protocol_version.txt
var protocolVersionContract string

// Request is the versioned-by-operation local lifecycle contract. It carries
// no gateway bearer token; authentication remains in the proxy sidecar.
type Request struct {
	Operation  string        `json:"operation"`
	InstanceID string        `json:"instance_id,omitempty"`
	ExitCode   int32         `json:"exit_code,omitempty"`
	Process    *ProcessEvent `json:"process,omitempty"`
	Peer       *PeerClaims   `json:"peer,omitempty"`
}

// PeerClaims repeat the VM identity inside the authenticated request protocol.
// The host checks these fields against the per-boot URI SAN and rejects nonce reuse.
type PeerClaims struct {
	Identity      string `json:"identity"`
	SandboxID     string `json:"sandbox_id"`
	SessionID     string `json:"session_id"`
	Generation    string `json:"generation"`
	ImageDigest   string `json:"image_digest"`
	RuntimeDigest string `json:"runtime_digest"`
	Protocol      uint32 `json:"protocol"`
	Nonce         string `json:"nonce"`
	IssuedAt      int64  `json:"issued_at_ms"`
}

type VMIdentity struct{ SandboxID, SessionID, Generation, ImageDigest, RuntimeDigest string }

func ParseVMIdentity(raw string) (VMIdentity, error) {
	var id VMIdentity
	if raw == "" || strings.TrimSpace(raw) != raw {
		return id, errors.New("supervisorcontrol: VM identity must be canonical")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "spiffe" || u.Host != "cautem.vm" || u.RawQuery != "" || u.Fragment != "" {
		return id, errors.New("supervisorcontrol: VM identity must be a canonical cautem.vm SPIFFE URI")
	}
	if u.String() != raw || u.User != nil || u.Opaque != "" {
		return id, errors.New("supervisorcontrol: VM identity URI is not canonical")
	}
	parts := strings.Split(u.EscapedPath(), "/")
	if len(parts) != 11 || parts[0] != "" || parts[1] != "sandbox" || parts[3] != "session" || parts[5] != "rootfs" || parts[7] != "runtime" || parts[9] != "generation" {
		return id, errors.New("supervisorcontrol: VM identity URI has invalid claims")
	}
	for _, value := range parts[2:] {
		if value == "" || strings.Contains(value, "%") {
			return id, errors.New("supervisorcontrol: VM identity URI contains invalid claim encoding")
		}
	}
	if !validSHA256IdentityDigest(parts[6]) || !validSHA256IdentityDigest(parts[8]) {
		return id, errors.New("supervisorcontrol: VM identity contains an invalid artifact digest")
	}
	session := strings.ReplaceAll(parts[4], "-", "")
	sessionBytes, err := hex.DecodeString(session)
	if !canonicalSessionUUID(parts[4]) || err != nil || len(sessionBytes) != 16 {
		return id, errors.New("supervisorcontrol: VM identity contains an invalid session")
	}
	if !validVMRuntimeGeneration(parts[10]) || strings.ToLower(parts[10]) != parts[10] {
		return id, errors.New("supervisorcontrol: VM identity contains an invalid generation")
	}
	id = VMIdentity{SandboxID: parts[2], SessionID: parts[4], ImageDigest: parts[6], RuntimeDigest: parts[8], Generation: parts[10]}
	return id, nil
}

func validVMRuntimeGeneration(raw string) bool {
	// Locally provisioned VMs use a random 128-bit generation. Gateway-owned
	// launch credentials use OpenShell's g-prefixed 64-bit generation.
	if len(raw) == 32 {
		decoded, err := hex.DecodeString(raw)
		return err == nil && len(decoded) == 16
	}
	if len(raw) != 17 || raw[0] != 'g' {
		return false
	}
	decoded, err := hex.DecodeString(raw[1:])
	return err == nil && len(decoded) == 8
}

func canonicalSessionUUID(raw string) bool {
	if len(raw) != 36 || strings.ToLower(raw) != raw || raw[8] != '-' || raw[13] != '-' || raw[18] != '-' || raw[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(raw, "-", "")
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return false
	}
	for _, value := range decoded {
		if value != 0 {
			return true
		}
	}
	return false
}

func validSHA256IdentityDigest(raw string) bool {
	if !strings.HasPrefix(raw, "sha256:") || strings.ToLower(raw) != raw {
		return false
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(raw, "sha256:"))
	return err == nil && len(digest) == 32
}

// ProcessEvent is a bounded observation from the sandbox PID 1. It deliberately
// excludes argv and environment values because those often contain secrets.
type ProcessEvent struct {
	InstanceID    string `json:"instance_id,omitempty"`
	Activity      string `json:"activity"`
	PID           int    `json:"pid"`
	ParentPID     int    `json:"parent_pid"`
	SupervisorPID int    `json:"supervisor_pid,omitempty"`
	Executable    string `json:"executable"`
	Timestamp     int64  `json:"timestamp_ms"`
}

// Response returns the sidecar's current process instance or RPC result.
type Response struct {
	InstanceID string `json:"instance_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Handler executes one request from PID 1.
type Handler func(context.Context, Request) Response

// Client routes requests over the local Unix socket or an authenticated TLS
// endpoint. Its credentials are loaded once so the calling workload process
// does not need access to the private key files.
type Client struct {
	socket        string
	endpoint      string
	privateDir    string
	clientKeyPath string
	tls           *tls.Config
	identity      string
}

// NewClientFromEnvironment selects the Unix socket or mutual TLS transport.
// TLS endpoint mode requires an explicit client CA, certificate, and key.
func NewClientFromEnvironment() (*Client, error) {
	socket := strings.TrimSpace(os.Getenv(EnvSocket))
	endpoint := strings.TrimSpace(os.Getenv(EnvEndpoint))
	if socket != "" && endpoint != "" {
		return nil, errors.New("supervisorcontrol: configure either a Unix socket or TLS endpoint, not both")
	}
	if endpoint == "" {
		hasTLSFiles := false
		for _, name := range []string{EnvClientCA, EnvClientCert, EnvClientKey} {
			if strings.TrimSpace(os.Getenv(name)) != "" {
				hasTLSFiles = true
			}
		}
		if socket == "" {
			if hasTLSFiles {
				return nil, errors.New("supervisorcontrol: TLS client files require a control socket or endpoint")
			}
			return nil, nil
		}
		if !hasTLSFiles {
			return &Client{socket: socket}, nil
		}
		caPath, certPath, keyPath := strings.TrimSpace(os.Getenv(EnvClientCA)), strings.TrimSpace(os.Getenv(EnvClientCert)), strings.TrimSpace(os.Getenv(EnvClientKey))
		credentialDir, err := validateClientCredentialPaths(caPath, certPath, keyPath)
		if err != nil {
			return nil, err
		}
		config, err := loadClientTLSConfig(caPath, certPath, keyPath)
		if err != nil {
			return nil, err
		}
		config.ServerName = unixServerName
		return &Client{socket: socket, privateDir: credentialDir, clientKeyPath: keyPath, tls: config, identity: vmIdentityFromClientTLS(config)}, nil
	}
	caPath := strings.TrimSpace(os.Getenv(EnvClientCA))
	certPath := strings.TrimSpace(os.Getenv(EnvClientCert))
	keyPath := strings.TrimSpace(os.Getenv(EnvClientKey))
	if caPath == "" || certPath == "" || keyPath == "" {
		return nil, errors.New("supervisorcontrol: TLS control endpoint requires client CA, certificate, and key")
	}
	credentialDir, err := validateClientCredentialPaths(caPath, certPath, keyPath)
	if err != nil {
		return nil, err
	}
	config, err := loadClientTLSConfig(caPath, certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &Client{endpoint: endpoint, privateDir: credentialDir, clientKeyPath: keyPath, tls: config, identity: vmIdentityFromClientTLS(config)}, nil
}

func vmIdentityFromClientTLS(config *tls.Config) string {
	if config == nil || len(config.Certificates) == 0 || len(config.Certificates[0].Certificate) == 0 {
		return ""
	}
	cert, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err != nil {
		return ""
	}
	for _, uri := range cert.URIs {
		if _, err := ParseVMIdentity(uri.String()); err == nil {
			return uri.String()
		}
	}
	return ""
}

func newPeerClaims(identity string) (PeerClaims, error) {
	id, err := ParseVMIdentity(identity)
	if err != nil {
		return PeerClaims{}, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return PeerClaims{}, fmt.Errorf("supervisorcontrol: generate request nonce: %w", err)
	}
	return PeerClaims{Identity: identity, SandboxID: id.SandboxID, SessionID: id.SessionID, Generation: id.Generation, ImageDigest: id.ImageDigest, RuntimeDigest: id.RuntimeDigest, Protocol: VMControlProtocol, Nonce: hex.EncodeToString(nonce[:]), IssuedAt: time.Now().UnixMilli()}, nil
}

// PeerGuard validates VM protocol claims and rejects stale or replayed requests.
type PeerGuard struct {
	expected string
	identity VMIdentity
	mu       sync.Mutex
	seen     map[string]time.Time
}

func NewPeerGuard(expectedIdentity string) (*PeerGuard, error) {
	identity, err := ParseVMIdentity(expectedIdentity)
	if err != nil {
		return nil, err
	}
	return &PeerGuard{expected: expectedIdentity, identity: identity, seen: make(map[string]time.Time)}, nil
}

func (g *PeerGuard) Validate(request Request) error {
	if g == nil {
		return nil
	}
	claims := request.Peer
	if claims == nil {
		return errors.New("supervisorcontrol: VM request is missing peer claims")
	}
	if claims.Identity != g.expected || claims.SandboxID != g.identity.SandboxID || claims.SessionID != g.identity.SessionID || claims.Generation != g.identity.Generation || claims.ImageDigest != g.identity.ImageDigest || claims.RuntimeDigest != g.identity.RuntimeDigest {
		return errors.New("supervisorcontrol: VM request claims do not match the authenticated peer")
	}
	if claims.Protocol != VMControlProtocol {
		return errors.New("supervisorcontrol: unsupported VM control protocol version")
	}
	nonce, err := hex.DecodeString(claims.Nonce)
	if err != nil || len(nonce) != 16 || strings.ToLower(claims.Nonce) != claims.Nonce {
		return errors.New("supervisorcontrol: VM request nonce is invalid")
	}
	issued := time.UnixMilli(claims.IssuedAt)
	if delta := time.Since(issued); delta > peerClaimsClockSkew || delta < -peerClaimsClockSkew {
		return errors.New("supervisorcontrol: VM request claims are expired or not yet valid")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for value, seenAt := range g.seen {
		if now.Sub(seenAt) > peerClaimsClockSkew {
			delete(g.seen, value)
		}
	}
	if _, exists := g.seen[claims.Nonce]; exists {
		return errors.New("supervisorcontrol: VM request nonce was already used")
	}
	if len(g.seen) >= maxPeerClaimNonces {
		return errors.New("supervisorcontrol: VM request replay cache is full")
	}
	g.seen[claims.Nonce] = issued
	return nil
}

func validateClientCredentialPaths(caPath, certPath, keyPath string) (string, error) {
	if caPath == "" || certPath == "" || keyPath == "" {
		return "", errors.New("supervisorcontrol: TLS client credentials require CA, certificate, and key")
	}
	credentialDir := filepath.Dir(certPath)
	for _, path := range []string{caPath, certPath, keyPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return "", errors.New("supervisorcontrol: TLS client credential paths must be absolute and clean")
		}
		if filepath.Dir(path) != credentialDir {
			return "", errors.New("supervisorcontrol: TLS client credentials must share one private directory")
		}
	}
	if credentialDir == string(filepath.Separator) {
		return "", errors.New("supervisorcontrol: TLS client credentials cannot be stored in the filesystem root")
	}
	return credentialDir, nil
}

// PrivateCredentialDir reports the directory whose filesystem access must be
// denied to the untrusted child process launched by PID 1.
func (c *Client) PrivateCredentialDir() string {
	if c == nil {
		return ""
	}
	return c.privateDir
}

// ConsumeClientCredentialKey removes the guest's bootstrap TLS private-key file
// after its key has been loaded into the trusted supervisor's memory.
func (c *Client) ConsumeClientCredentialKey() error {
	if c == nil || c.socket == "" || c.tls == nil || c.clientKeyPath == "" {
		return nil
	}
	if err := os.Remove(c.clientKeyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("supervisorcontrol: consume client private key: %w", err)
	}
	return nil
}

// Call sends one request using the selected transport.
func (c *Client) Call(ctx context.Context, request Request) (Response, error) {
	if c == nil {
		return Response{}, errors.New("supervisorcontrol: client is nil")
	}
	if c.identity != "" {
		claims, err := newPeerClaims(c.identity)
		if err != nil {
			return Response{}, err
		}
		request.Peer = &claims
	}
	if c.socket != "" {
		if c.tls != nil {
			return CallTLSUnix(ctx, c.socket, c.tls, request)
		}
		return Call(ctx, c.socket, request)
	}
	if c.endpoint != "" {
		return CallTLS(ctx, c.endpoint, c.tls, request)
	}
	return Response{}, errors.New("supervisorcontrol: control transport is not configured")
}

// ServerTLSConfigFromEnvironment loads the server identity and client trust
// anchor mounted into the trusted supervisor process.
func ServerTLSConfigFromEnvironment() (*tls.Config, error) {
	config, err := loadServerTLSConfig(
		strings.TrimSpace(os.Getenv(EnvServerCA)),
		strings.TrimSpace(os.Getenv(EnvServerCert)),
		strings.TrimSpace(os.Getenv(EnvServerKey)),
	)
	if err != nil {
		return nil, err
	}
	expected := strings.TrimSpace(os.Getenv(EnvExpectedClientIdentity))
	if expected != "" {
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("supervisorcontrol: client certificate is missing")
			}
			for _, uri := range state.PeerCertificates[0].URIs {
				if uri.String() == expected {
					return nil
				}
			}
			return errors.New("supervisorcontrol: client certificate identity does not match this VM")
		}
	}
	return config, nil
}

func loadClientTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("supervisorcontrol: read client trust anchor: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("supervisorcontrol: client trust anchor contains no certificates")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("supervisorcontrol: load client identity: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert}}, nil
}

func loadServerTLSConfig(clientCAPath, certPath, keyPath string) (*tls.Config, error) {
	if clientCAPath == "" || certPath == "" || keyPath == "" {
		return nil, errors.New("supervisorcontrol: TLS server requires client CA, server certificate, and key")
	}
	clientCAPEM, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, fmt.Errorf("supervisorcontrol: read server client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, errors.New("supervisorcontrol: server client CA contains no certificates")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("supervisorcontrol: load server identity: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}, nil
}

// StartTLSUnix serves the control protocol over a private Unix socket with mutual TLS.
func StartTLSUnix(ctx context.Context, path string, config *tls.Config, handler Handler) (*Server, error) {
	if config == nil {
		return nil, errors.New("supervisorcontrol: mutual TLS configuration is required")
	}
	if err := validateServerTLSConfig(config); err != nil {
		return nil, err
	}
	return startUnix(ctx, path, config, handler)
}

func validateServerTLSConfig(config *tls.Config) error {
	tlsConfig := config.Clone()
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	if tlsConfig.MinVersion < tls.VersionTLS12 || tlsConfig.InsecureSkipVerify || tlsConfig.GetConfigForClient != nil || tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.ClientCAs == nil {
		return errors.New("supervisorcontrol: TLS 1.2+ and verified client certificates are required")
	}
	if len(tlsConfig.Certificates) == 0 && tlsConfig.GetCertificate == nil {
		return errors.New("supervisorcontrol: server certificate is required")
	}
	return nil
}

// CallTLSUnix sends a request over a Unix socket after mutual TLS authentication.
func CallTLSUnix(ctx context.Context, path string, config *tls.Config, request Request) (Response, error) {
	var response Response
	if strings.TrimSpace(path) == "" || config == nil {
		return response, errors.New("supervisorcontrol: authenticated TLS socket and configuration are required")
	}
	tlsConfig := config.Clone()
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	if tlsConfig.MinVersion < tls.VersionTLS12 || tlsConfig.InsecureSkipVerify || (len(tlsConfig.Certificates) == 0 && tlsConfig.GetClientCertificate == nil) {
		return response, errors.New("supervisorcontrol: TLS 1.2+ and a client certificate are required")
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return response, fmt.Errorf("supervisorcontrol: connect using authenticated TLS: %w", err)
	}
	conn := tls.Client(raw, tlsConfig)
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return response, fmt.Errorf("supervisorcontrol: TLS handshake: %w", err)
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return response, fmt.Errorf("supervisorcontrol: send request: %w", err)
	}
	decoder := json.NewDecoder(io.LimitReader(conn, maxMessageBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return response, fmt.Errorf("supervisorcontrol: receive response: %w", err)
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

// Server serves bounded lifecycle requests on a Unix socket or authenticated TLS listener.
type Server struct {
	listener net.Listener
	path     string
	fileInfo os.FileInfo
	once     sync.Once
	done     chan struct{}
}

// Addr reports the bound address. For Unix sockets it returns the socket path;
// for TCP listeners it includes the selected port.
func (s *Server) Addr() net.Addr {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Start binds the socket synchronously, then accepts requests until ctx ends.
func Start(ctx context.Context, path string, handler Handler) (*Server, error) {
	return startUnix(ctx, path, nil, handler)
}

func startUnix(ctx context.Context, path string, config *tls.Config, handler Handler) (*Server, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || handler == nil {
		return nil, errors.New("supervisorcontrol: an absolute clean socket path and handler are required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("supervisorcontrol: create socket directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("supervisorcontrol: refusing to replace a non-socket path")
		}
		conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, errors.New("supervisorcontrol: another control server is already listening")
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("supervisorcontrol: remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("supervisorcontrol: inspect socket path: %w", err)
	}
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	unixListener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("supervisorcontrol: listen: %w", err)
	}
	var listener net.Listener = unixListener
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("supervisorcontrol: restrict socket permissions: %w", err)
	}
	if config != nil {
		listener = tls.NewListener(listener, config.Clone())
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("supervisorcontrol: inspect bound socket: %w", err)
	}
	return startServer(ctx, listener, path, info, handler), nil
}

// StartTLS serves the same bounded control protocol over a mutually
// authenticated TLS connection. It is intended for trusted components that
// cannot share a filesystem socket, such as a workload and its Kubernetes
// supervisor Pod. The caller must configure a server certificate and a client
// CA pool; unauthenticated TLS modes are rejected.
func StartTLS(ctx context.Context, address string, config *tls.Config, handler Handler) (*Server, error) {
	address = strings.TrimSpace(address)
	if address == "" || handler == nil {
		return nil, errors.New("supervisorcontrol: a TCP address and handler are required")
	}
	if config == nil {
		return nil, errors.New("supervisorcontrol: mutual TLS configuration is required")
	}
	tlsConfig := config.Clone()
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	if tlsConfig.MinVersion < tls.VersionTLS12 || tlsConfig.InsecureSkipVerify || tlsConfig.GetConfigForClient != nil || tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.ClientCAs == nil {
		return nil, errors.New("supervisorcontrol: TLS 1.2+ and verified client certificates are required")
	}
	if len(tlsConfig.Certificates) == 0 && tlsConfig.GetCertificate == nil {
		return nil, errors.New("supervisorcontrol: server certificate is required")
	}
	listener, err := tls.Listen("tcp", address, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("supervisorcontrol: listen for authenticated TLS control: %w", err)
	}
	return startServer(ctx, listener, "", nil, handler), nil
}

func startServer(ctx context.Context, listener net.Listener, path string, fileInfo os.FileInfo, handler Handler) *Server {
	server := &Server{listener: listener, path: path, fileInfo: fileInfo, done: make(chan struct{})}
	go server.serve(ctx, handler)
	return server
}

func (s *Server) serve(ctx context.Context, handler Handler) {
	defer close(s.done)
	semaphore := make(chan struct{}, 16)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
		case <-s.done:
		}
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				defer conn.Close()
				s.handle(ctx, conn, handler)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn, handler Handler) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(io.LimitReader(conn, maxMessageBytes+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > maxMessageBytes {
		_ = json.NewEncoder(conn).Encode(Response{Error: "invalid or oversized request"})
		return
	}
	var request Request
	decoder := json.NewDecoder(strings.NewReader(string(line)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{Error: "invalid request"})
		return
	}
	response := handler(ctx, request)
	_ = json.NewEncoder(conn).Encode(response)
}

// Close stops accepting requests and removes only this server's socket inode.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var closeErr error
	s.once.Do(func() {
		closeErr = s.listener.Close()
		<-s.done
		if info, err := os.Lstat(s.path); err == nil && os.SameFile(info, s.fileInfo) {
			if removeErr := os.Remove(s.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && closeErr == nil {
				closeErr = removeErr
			}
		}
	})
	return closeErr
}

// Call sends one request and waits for its response using ctx for dial and I/O
// deadlines. A response-level error is returned as a Go error.
func Call(ctx context.Context, path string, request Request) (Response, error) {
	var response Response
	if strings.TrimSpace(path) == "" {
		return response, errors.New("supervisorcontrol: socket path is required")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return response, fmt.Errorf("supervisorcontrol: connect: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return response, fmt.Errorf("supervisorcontrol: send request: %w", err)
	}
	decoder := json.NewDecoder(io.LimitReader(conn, maxMessageBytes))
	if err := decoder.Decode(&response); err != nil {
		return response, fmt.Errorf("supervisorcontrol: receive response: %w", err)
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

// CallTLS sends one control request to a mutually authenticated TLS server.
// The client certificate authenticates the caller, and the server certificate
// is verified against RootCAs or the platform trust store.
func CallTLS(ctx context.Context, address string, config *tls.Config, request Request) (Response, error) {
	var response Response
	address = strings.TrimSpace(address)
	if address == "" || config == nil {
		return response, errors.New("supervisorcontrol: authenticated TLS address and configuration are required")
	}
	tlsConfig := config.Clone()
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	if tlsConfig.MinVersion < tls.VersionTLS12 || tlsConfig.InsecureSkipVerify || (len(tlsConfig.Certificates) == 0 && tlsConfig.GetClientCertificate == nil) {
		return response, errors.New("supervisorcontrol: TLS 1.2+ and a client certificate are required")
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return response, fmt.Errorf("supervisorcontrol: connect using authenticated TLS: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return response, fmt.Errorf("supervisorcontrol: send request: %w", err)
	}
	decoder := json.NewDecoder(io.LimitReader(conn, maxMessageBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return response, fmt.Errorf("supervisorcontrol: receive response: %w", err)
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

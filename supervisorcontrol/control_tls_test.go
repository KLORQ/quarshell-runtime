package supervisorcontrol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMutuallyAuthenticatedControlTLS(t *testing.T) {
	caCert, caKey := newTestCA(t)
	serverCert := newTestCertificate(t, caCert, caKey, true)
	clientCert := newTestCertificate(t, caCert, caKey, false)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(caCert)
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(caCert)

	server, err := StartTLS(context.Background(), "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
	}, func(_ context.Context, request Request) Response {
		if request.Operation != OperationBegin {
			return Response{Error: "unexpected operation"}
		}
		return Response{InstanceID: "instance-1"}
	})
	if err != nil {
		t.Fatalf("StartTLS() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	address := server.listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, err := CallTLS(ctx, address, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      serverRoots,
		ServerName:   "localhost",
	}, Request{Operation: OperationBegin})
	if err != nil {
		t.Fatalf("CallTLS() error = %v", err)
	}
	if response.InstanceID != "instance-1" {
		t.Fatalf("CallTLS() instance ID = %q, want instance-1", response.InstanceID)
	}
}

func TestMutuallyAuthenticatedControlTLSOverUnix(t *testing.T) {
	caCert, caKey := newTestCA(t)
	serverCert := newTestCertificate(t, caCert, caKey, true)
	clientCert := newTestCertificate(t, caCert, caKey, false)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	clientIdentity, _ := url.Parse("spiffe://cautem.vm/sandbox/demo/session/11234567-89ab-cdef-0123-456789abcdef/rootfs/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/runtime/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/generation/0123456789abcdef0123456789abcdef")
	serverConfig := func(expected string) *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
			VerifyConnection: func(state tls.ConnectionState) error {
				for _, uri := range state.PeerCertificates[0].URIs {
					if uri.String() == expected {
						return nil
					}
				}
				return errors.New("wrong VM identity")
			},
		}
	}
	path := testSocketPath(t)
	badServer, err := StartTLSUnix(context.Background(), path+"-bad", serverConfig("spiffe://cautem.vm/sandbox/other"), func(context.Context, Request) Response { return Response{InstanceID: "wrong"} })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{clientCert}, RootCAs: roots, ServerName: unixServerName}
	if _, err := CallTLSUnix(ctx, path+"-bad", config, Request{Operation: OperationBegin}); err == nil {
		t.Fatal("TLS Unix accepted a client from another VM generation")
	}
	_ = badServer.Close()
	server, err := StartTLSUnix(context.Background(), path, serverConfig(clientIdentity.String()), func(context.Context, Request) Response { return Response{InstanceID: "vm-1"} })
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	response, err := CallTLSUnix(ctx, path, config, Request{Operation: OperationBegin})
	if err != nil || response.InstanceID != "vm-1" {
		t.Fatalf("CallTLSUnix() = (%+v, %v)", response, err)
	}
}

func TestVMClientCarriesVersionedClaimsOverMTLS(t *testing.T) {
	ca, caKey := newTestCA(t)
	serverCert := newTestCertificate(t, ca, caKey, true)
	clientCert := newTestCertificate(t, ca, caKey, false)
	clientLeaf, err := x509.ParseCertificate(clientCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	identity := clientLeaf.URIs[0].String()
	guard, err := NewPeerGuard(identity)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	path := testSocketPath(t)
	server, err := StartTLSUnix(context.Background(), path, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}, func(_ context.Context, request Request) Response {
		if err := guard.Validate(request); err != nil {
			return Response{Error: err.Error()}
		}
		return Response{InstanceID: request.Peer.Generation}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	clientDir := t.TempDir()
	caPath := writeCertificateFile(t, filepath.Join(clientDir, "ca.pem"), ca.Raw)
	clientCertPath, clientKeyPath := writeKeyPairFilesInDir(t, clientDir, "client", clientCert)
	t.Setenv(EnvSocket, path)
	t.Setenv(EnvEndpoint, "")
	t.Setenv(EnvClientCA, caPath)
	t.Setenv(EnvClientCert, clientCertPath)
	t.Setenv(EnvClientKey, clientKeyPath)
	client, err := NewClientFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if client.PrivateCredentialDir() != clientDir {
		t.Fatalf("private credential directory=%q, want %q", client.PrivateCredentialDir(), clientDir)
	}
	if err := client.ConsumeClientCredentialKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(clientKeyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bootstrap key remains after consume: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, err := client.Call(ctx, Request{Operation: OperationBegin})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseVMIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	if response.InstanceID != parsed.Generation {
		t.Fatalf("response generation=%q want %q", response.InstanceID, parsed.Generation)
	}
}

func TestControlTLSRejectsUntrustedClientAndUnsafeConfig(t *testing.T) {
	serverCACert, serverCAKey := newTestCA(t)
	serverCert := newTestCertificate(t, serverCACert, serverCAKey, true)
	clientCACert, clientCAKey := newTestCA(t)
	untrustedClientCert := newTestCertificate(t, clientCACert, clientCAKey, false)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(serverCACert)
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(serverCACert)

	baseConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
	}
	if _, err := StartTLS(context.Background(), "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}, func(context.Context, Request) Response { return Response{} }); err == nil {
		t.Fatal("StartTLS() accepted a server that does not verify client certificates")
	}
	if _, err := CallTLS(context.Background(), "127.0.0.1:1", &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{untrustedClientCert}}, Request{}); err == nil {
		t.Fatal("CallTLS() accepted insecure server-certificate verification")
	}

	server, err := StartTLS(context.Background(), "127.0.0.1:0", baseConfig, func(context.Context, Request) Response {
		return Response{InstanceID: "should-not-run"}
	})
	if err != nil {
		t.Fatalf("StartTLS() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = CallTLS(ctx, server.listener.Addr().String(), &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{untrustedClientCert},
		RootCAs:      serverRoots,
		ServerName:   "localhost",
	}, Request{Operation: OperationBegin})
	if err == nil {
		t.Fatal("CallTLS() succeeded with a client certificate outside the configured trust pool")
	}
}

func TestTLSConfigurationLoadsOnlyCompleteEnvironmentBundles(t *testing.T) {
	t.Setenv(EnvEndpoint, "supervisor.default.svc:5502")
	if _, err := NewClientFromEnvironment(); err == nil {
		t.Fatal("NewClientFromEnvironment() accepted an incomplete client bundle")
	}

	ca, caKey := newTestCA(t)
	serverCert := newTestCertificate(t, ca, caKey, true)
	clientCert := newTestCertificate(t, ca, caKey, false)
	clientDir := t.TempDir()
	caPath := writeCertificateFile(t, filepath.Join(clientDir, "ca.pem"), ca.Raw)
	serverCertPath, serverKeyPath := writeKeyPairFiles(t, "server", serverCert)
	clientCertPath, clientKeyPath := writeKeyPairFilesInDir(t, clientDir, "client", clientCert)

	t.Setenv(EnvClientCA, caPath)
	t.Setenv(EnvClientCert, clientCertPath)
	t.Setenv(EnvClientKey, clientKeyPath)
	client, err := NewClientFromEnvironment()
	if err != nil {
		t.Fatalf("NewClientFromEnvironment() error = %v", err)
	}
	if client.endpoint != "supervisor.default.svc:5502" || client.tls == nil || len(client.tls.Certificates) != 1 || client.tls.RootCAs == nil {
		t.Fatalf("loaded client configuration = %+v", client)
	}

	t.Setenv(EnvServerCA, caPath)
	t.Setenv(EnvServerCert, serverCertPath)
	t.Setenv(EnvServerKey, serverKeyPath)
	serverTLS, err := ServerTLSConfigFromEnvironment()
	if err != nil {
		t.Fatalf("ServerTLSConfigFromEnvironment() error = %v", err)
	}
	if serverTLS.ClientAuth != tls.RequireAndVerifyClientCert || serverTLS.ClientCAs == nil || len(serverTLS.Certificates) != 1 {
		t.Fatalf("loaded server configuration is not mutually authenticated: %+v", serverTLS)
	}

	for _, name := range []string{EnvEndpoint, EnvClientCA, EnvClientCert, EnvClientKey, EnvServerCA, EnvServerCert, EnvServerKey} {
		t.Setenv(name, "")
	}
	t.Setenv(EnvClientCert, clientCertPath)
	if _, err := NewClientFromEnvironment(); err == nil {
		t.Fatal("NewClientFromEnvironment() accepted client files without an endpoint")
	}
}

func writeCertificateFile(t *testing.T, path string, der []byte) string {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeKeyPairFiles(t *testing.T, prefix string, cert tls.Certificate) (string, string) {
	t.Helper()
	return writeKeyPairFilesInDir(t, t.TempDir(), prefix, cert)
}

func writeKeyPairFilesInDir(t *testing.T, root, prefix string, cert tls.Certificate) (string, string) {
	t.Helper()
	certPath := filepath.Join(root, prefix+".crt")
	keyPath := filepath.Join(root, prefix+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func newTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "control-test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate(CA) error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(CA) error = %v", err)
	}
	return cert, key
}

func newTestCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "control-test-peer"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usage,
	}
	if server {
		template.DNSNames = []string{"localhost", unixServerName}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if !server {
		uri, _ := url.Parse("spiffe://cautem.vm/sandbox/demo/session/11234567-89ab-cdef-0123-456789abcdef/rootfs/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/runtime/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/generation/0123456789abcdef0123456789abcdef")
		template.URIs = []*url.URL{uri}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(peer) error = %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

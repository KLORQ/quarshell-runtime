//go:build !windows

package supervisorcontrol

import (
	"context"
	"os"
	"testing"
)

func TestStartRestrictsSocketPermissions(t *testing.T) {
	path := testSocketPath(t)
	server, err := Start(context.Background(), path, func(context.Context, Request) Response { return Response{} })
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode %o, want 600", got)
	}
}

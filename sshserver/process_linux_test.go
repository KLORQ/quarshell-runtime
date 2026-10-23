//go:build linux

package sshserver

import (
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

type processTestSSHChannel struct {
	input io.Reader
}

func (c *processTestSSHChannel) Read(payload []byte) (int, error)  { return c.input.Read(payload) }
func (c *processTestSSHChannel) Write(payload []byte) (int, error) { return len(payload), nil }
func (c *processTestSSHChannel) Close() error                      { return nil }
func (c *processTestSSHChannel) CloseWrite() error                 { return nil }
func (c *processTestSSHChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (c *processTestSSHChannel) Stderr() io.ReadWriter { return &processTestReadWriter{} }

type processTestReadWriter struct{}

func (*processTestReadWriter) Read([]byte) (int, error)          { return 0, io.EOF }
func (*processTestReadWriter) Write(payload []byte) (int, error) { return len(payload), nil }

func TestProcessWaitReturnsStableExitStatusConcurrently(t *testing.T) {
	channel := &processTestSSHChannel{input: strings.NewReader("")}
	child, err := startProcess([]string{"/bin/sh", "-c", "exit 42"}, os.Environ(), t.TempDir(), nil, channel)
	if err != nil {
		t.Fatalf("start process: %v", err)
	}

	const callers = 8
	results := make(chan int, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for range callers {
		go func() {
			defer wait.Done()
			results <- child.wait()
		}()
	}
	wait.Wait()
	close(results)
	for result := range results {
		if result != 42 {
			t.Fatalf("process wait returned %d, want stable exit status 42", result)
		}
	}
}

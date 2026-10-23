//go:build !windows

package wsinit

import (
	"os"
	"strconv"
	"syscall"
	"testing"
)

func TestWaitForHostStartGateReadsOneShotPipeConfirmation(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	fd, err := syscall.Dup(int(reader.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	t.Setenv(hostStartGateFDEnv, strconv.Itoa(fd))
	if _, err := writer.WriteString("confirmed\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitForHostStartGate(); err != nil {
		t.Fatalf("waitForHostStartGate() error=%v", err)
	}
}

func TestWaitForHostStartGateRejectsUnconfirmedPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Dup(int(reader.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	t.Setenv(hostStartGateFDEnv, strconv.Itoa(fd))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitForHostStartGate(); err == nil {
		t.Fatal("accepted an empty start gate")
	}
}

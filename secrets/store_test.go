package secrets

import (
	"context"
	"errors"
	"testing"
)

func TestMapStore(t *testing.T) {
	s := MapStore{"TOKEN": "abc"}
	v, err := s.Get(context.Background(), "TOKEN")
	if err != nil || v != "abc" {
		t.Fatalf("got %q err=%v", v, err)
	}
	_, err = s.Get(context.Background(), "missing")
	var nf ErrNotFound
	if !errors.As(err, &nf) || nf.Key != "missing" {
		t.Fatalf("err=%v", err)
	}
}

func TestEnvStore(t *testing.T) {
	s := EnvStore{Environ: []string{"FOO=bar", "BAZ=qux"}}
	v, err := s.Get(context.Background(), "FOO")
	if err != nil || v != "bar" {
		t.Fatalf("got %q err=%v", v, err)
	}
}

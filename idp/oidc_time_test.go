package idp

import (
	"strings"
	"testing"
	"time"
)

func TestValidateTokenTimesWithLeeway(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name   string
		claim  string
		delta  time.Duration
		denied bool
	}{
		{"expired beyond leeway", "exp", -91 * time.Second, true},
		{"expired within leeway", "exp", -89 * time.Second, false},
		{"not yet valid", "nbf", 91 * time.Second, true},
		{"nbf within leeway", "nbf", 89 * time.Second, false},
		{"issued in future", "iat", 91 * time.Second, true},
		{"iat within leeway", "iat", 89 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTokenTimes(map[string]any{tc.claim: float64(now.Add(tc.delta).Unix())}, now)
			if (err != nil) != tc.denied {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
	if err := validateTokenTimes(map[string]any{"nbf": "tomorrow"}, now); err == nil || !strings.Contains(err.Error(), "invalid nbf") {
		t.Fatalf("invalid nbf accepted: %v", err)
	}
}

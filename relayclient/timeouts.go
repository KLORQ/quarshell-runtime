package relayclient

import "time"

// Operational defaults owned by this package.
const (
	defaultMaxBackoff = 30 * time.Second
	relayDialTimeout  = 10 * time.Second
)

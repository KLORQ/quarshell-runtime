package sshserver

import "time"

// Operational defaults owned by this package.
const (
	sessionRequestTimeout = 10 * time.Second
	handshakeTimeout      = 30 * time.Second
)

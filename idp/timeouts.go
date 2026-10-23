package idp

import "time"

// Operational defaults owned by this package.
const (
	oidcRequestTimeout        = 15 * time.Second
	defaultJWKSCacheTTL       = 10 * time.Minute
	oauthRequestTimeout       = 20 * time.Second
	defaultLoginTimeout       = 3 * time.Minute
	callbackHeaderReadTimeout = 5 * time.Second
	callbackShutdownTimeout   = 2 * time.Second
)

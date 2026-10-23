// Package refresh provides host-environment credential re-injection.
package refresh

// Result is one refreshed secret.
type Result struct {
	Key   string
	Value string
}

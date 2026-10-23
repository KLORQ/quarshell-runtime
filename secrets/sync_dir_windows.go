//go:build windows

package secrets

// os.File.Sync does not support Windows directory handles.
func syncDirectory(string) error { return nil }

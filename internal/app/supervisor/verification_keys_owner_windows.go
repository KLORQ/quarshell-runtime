//go:build windows

package supervisor

import "os"

// The VM guest supervisor and its Unix ownership contract run on Linux. A
// Windows build must fail closed if a caller attempts to use that VM-only key
// bundle path because this package does not verify Windows ACL ownership.
func ownedByEffectiveIdentity(os.FileInfo) bool { return false }

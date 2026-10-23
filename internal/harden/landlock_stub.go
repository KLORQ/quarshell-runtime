//go:build !linux

package harden

import (
	"errors"

	"github.com/KLORQ/quarshell-policy/corepolicy"
)

var errLandlockUnavailable = errors.New("landlock only available on linux")

func landlockABI() (int, error) {
	return 0, errLandlockUnavailable
}

func applyLandlockWithMode(_ policy.Document, _ int, _ Mode) error {
	return errLandlockUnavailable
}

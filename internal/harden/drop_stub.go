//go:build !linux

package harden

import "errors"

import "github.com/KLORQ/quarshell-policy/corepolicy"

var errPrivilegeDropUnavailable = errors.New("privilege drop only available on linux")

func dropPrivileges(_ policy.Document) error {
	return errPrivilegeDropUnavailable
}

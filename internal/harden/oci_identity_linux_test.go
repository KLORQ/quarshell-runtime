//go:build linux

package harden

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestResolveOCIImageUserNumericPair(t *testing.T) {
	uid, gid, err := resolveOCIImageUser("1234:1235", true, true)
	if err != nil || uid != 1234 || gid != 1235 {
		t.Fatalf("got %d:%d, %v", uid, gid, err)
	}
}

func TestResolveOCIImageUserNamedUserAndPrimaryGroup(t *testing.T) {
	entry, err := nonRootTestUser()
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, err := resolveOCIImageUser(entry.Username, true, true)
	if err != nil {
		t.Fatal(err)
	}
	wantUID, _ := strconv.Atoi(entry.Uid)
	wantGID, _ := strconv.Atoi(entry.Gid)
	if uid != wantUID || gid != wantGID {
		t.Fatalf("got %d:%d, want %d:%d", uid, gid, wantUID, wantGID)
	}
}

func TestResolveOCIImageUserMixedNamedAndNumericComponents(t *testing.T) {
	entry, err := nonRootTestUser()
	if err != nil {
		t.Fatal(err)
	}
	uidWant, _ := strconv.Atoi(entry.Uid)
	uid, gid, err := resolveOCIImageUser(entry.Username+":1235", true, true)
	if err != nil || uid != uidWant || gid != 1235 {
		t.Fatalf("named:numeric = %d:%d, %v", uid, gid, err)
	}
	uid, gid, err = resolveOCIImageUser("1234:"+entry.Gid, true, true)
	if err != nil || uid != 1234 {
		t.Fatalf("numeric:named = %d:%d, %v", uid, gid, err)
	}
	group, err := user.LookupGroupId(entry.Gid)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, err = resolveOCIImageUser("1234:"+group.Name, true, true)
	wantGID, _ := strconv.Atoi(entry.Gid)
	if err != nil || uid != 1234 || gid != wantGID {
		t.Fatalf("numeric:named-group = %d:%d, %v", uid, gid, err)
	}
}

func nonRootTestUser() (*user.User, error) {
	for _, name := range []string{"sandbox", "nobody"} {
		entry, err := user.Lookup(name)
		if err == nil && entry.Uid != "0" {
			return entry, nil
		}
	}
	return nil, user.UnknownUserError("non-root test identity")
}

func TestResolveOCIImageUserIgnoresExplicitPolicyComponent(t *testing.T) {
	_, gid, err := resolveOCIImageUser("bad user:1235", false, true)
	if err != nil || gid != 1235 {
		t.Fatalf("got GID %d, %v", gid, err)
	}
	uid, _, err := resolveOCIImageUser("1234:bad group", true, false)
	if err != nil || uid != 1234 {
		t.Fatalf("got UID %d, %v", uid, err)
	}
}

func TestResolveOCIImageUserRejectsMalformedSelectedComponents(t *testing.T) {
	for _, raw := range []string{"bad user:1235", "1234:bad group"} {
		needUser, needGroup := false, false
		if strings.HasPrefix(raw, "bad user") {
			needUser = true
			needGroup = false
		} else {
			needUser = false
			needGroup = true
		}
		if _, _, err := resolveOCIImageUser(raw, needUser, needGroup); err == nil {
			t.Errorf("selected malformed OCI component %q unexpectedly accepted", raw)
		}
	}
}

func TestResolveOCIImageUserRejectsRootAndMalformedSelectedComponents(t *testing.T) {
	for _, raw := range []string{"0:1234", "1234:0", "4294967295:1234", "1234:4294967295", "", "1:2:3"} {
		if _, _, err := resolveOCIImageUser(raw, true, true); err == nil {
			t.Errorf("%q unexpectedly accepted", raw)
		}
	}
}

func TestResolveOCISupplementaryGIDsUsesNamedGroupMembership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "group")
	if err := os.WriteFile(path, []byte("primary:x:1235:\nextra:x:1236:app,other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveOCISupplementaryGIDsFrom("app:primary", 1235, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 1235 || got[1] != 1236 {
		t.Fatalf("supplementary GIDs = %v, want [1235 1236]", got)
	}
}

func TestResolveOCISupplementaryGIDsRejectsRootMembership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "group")
	if err := os.WriteFile(path, []byte("root:x:0:app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveOCISupplementaryGIDsFrom("app", 1235, path); err == nil {
		t.Fatal("OCI user membership in GID 0 unexpectedly accepted")
	}
}

func TestResolveOCISupplementaryGIDsSkipsNSSForNumericUser(t *testing.T) {
	got, err := resolveOCISupplementaryGIDsFrom("1234:1235", 1235, filepath.Join(t.TempDir(), "missing-group"))
	if err != nil || len(got) != 0 {
		t.Fatalf("numeric OCI user supplementary GIDs = %v, %v; want none", got, err)
	}
}

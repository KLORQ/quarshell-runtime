//go:build linux

package harden

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

const (
	maxAccountFileSize  = 1 << 20
	maxAccountLineSize  = 8 << 10
	maxAccountFieldSize = 1 << 10
)

// resolveOCIImageUser applies OCI USER components only where policy omitted
// them. Account files are parsed directly and bounded; NSS is not consulted.
func resolveOCIImageUser(raw string, needUser, needGroup bool) (uid, gid int, err error) {
	parts := strings.Split(raw, ":")
	if len(parts) > 2 {
		return 0, 0, fmt.Errorf("%s %q is malformed", ociImageUserEnv, raw)
	}
	if len(parts) == 0 {
		return 0, 0, fmt.Errorf("%s %q is malformed", ociImageUserEnv, raw)
	}
	userPart := parts[0]
	groupPart := ""
	if len(parts) == 2 {
		groupPart = parts[1]
	}
	var passwd map[string][2]int
	if needUser || (needGroup && groupPart == "") {
		passwd, err = parsePasswdFile("/etc/passwd")
		if err != nil {
			return 0, 0, err
		}
	}
	if needUser {
		if err := validateOCIComponent(userPart); err != nil {
			return 0, 0, fmt.Errorf("%s user: %w", ociImageUserEnv, err)
		}
		uid, _, err = resolveAccountComponent(userPart, passwd, false)
		if err != nil {
			return 0, 0, fmt.Errorf("%s user: %w", ociImageUserEnv, err)
		}
		if uid < 1 || uint64(uid) > maxProcessIdentity {
			return 0, 0, fmt.Errorf("%s user resolves outside [1, 4294967294]", ociImageUserEnv)
		}
	}
	if needGroup {
		if groupPart == "" {
			if err := validateOCIComponent(userPart); err != nil {
				return 0, 0, fmt.Errorf("%s user: %w", ociImageUserEnv, err)
			}
			if _, ok := passwd[userPart]; !ok {
				return 0, 0, fmt.Errorf("%s user %q has no passwd entry for primary GID", ociImageUserEnv, userPart)
			}
			gid = passwd[userPart][1]
		} else {
			if err := validateOCIComponent(groupPart); err != nil {
				return 0, 0, fmt.Errorf("%s group: %w", ociImageUserEnv, err)
			}
			gid, err = resolveGroupComponent(groupPart)
			if err != nil {
				return 0, 0, fmt.Errorf("%s group: %w", ociImageUserEnv, err)
			}
		}
		if gid < 1 || uint64(gid) > maxProcessIdentity {
			return 0, 0, fmt.Errorf("%s group resolves outside [1, 4294967294]", ociImageUserEnv)
		}
	}
	return uid, gid, nil
}

func resolveOCISupplementaryGIDs(declaration string, primaryGID int) ([]int, error) {
	return resolveOCISupplementaryGIDsFrom(declaration, primaryGID, "/etc/group")
}

func resolveOCISupplementaryGIDsFrom(declaration string, primaryGID int, path string) ([]int, error) {
	userName, _, hasGroup := strings.Cut(declaration, ":")
	if err := validateOCIComponent(userName); err != nil {
		return nil, fmt.Errorf("%s user: %w", ociImageUserEnv, err)
	}
	if _, err := strconv.Atoi(userName); err == nil {
		return nil, nil
	}
	lines, err := boundedLines(path)
	if err != nil {
		return nil, err
	}
	gids := []int{primaryGID}
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > maxAccountLineSize {
			return nil, fmt.Errorf("group membership entry in %s exceeds size limit", path)
		}
		fields := strings.Split(line, ":")
		if len(fields) != 4 || hasOversizedAccountField(fields) {
			return nil, fmt.Errorf("group membership entry in %s is malformed", path)
		}
		members := strings.Split(fields[3], ",")
		member := false
		for _, candidate := range members {
			if candidate == userName {
				member = true
				break
			}
		}
		if !member {
			continue
		}
		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("group membership GID in %s is malformed", path)
		}
		if gid == 0 {
			return nil, fmt.Errorf("OCI user %q belongs to prohibited GID 0", userName)
		}
		if gid < 0 || uint64(gid) > maxProcessIdentity {
			return nil, fmt.Errorf("OCI user %q belongs to GID outside [1, 4294967294]", userName)
		}
		gids = append(gids, gid)
	}
	if hasGroup && primaryGID == 0 {
		return nil, fmt.Errorf("OCI group resolves to prohibited GID 0")
	}
	sort.Ints(gids)
	return uniqueInts(gids), nil
}

func validateOCIComponent(value string) error {
	if value == "" || len(value) > maxAccountFieldSize || strings.TrimSpace(value) != value {
		return fmt.Errorf("component %q is malformed", value)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == ':' {
			return fmt.Errorf("component %q is malformed", value)
		}
	}
	return nil
}

func resolveAccountComponent(value string, entries map[string][2]int, group bool) (int, int, error) {
	if n, err := strconv.Atoi(value); err == nil {
		if n <= 0 || uint64(n) > maxProcessIdentity {
			return 0, 0, fmt.Errorf("identity %q is not a non-root numeric ID", value)
		}
		if group {
			return n, 0, nil
		}
		for _, pair := range entries {
			if pair[0] == n {
				return n, pair[1], nil
			}
		}
		return n, 0, nil
	}
	pair, ok := entries[value]
	if !ok {
		return 0, 0, fmt.Errorf("identity %q is unresolved", value)
	}
	return pair[0], pair[1], nil
}

func resolveGroupComponent(value string) (int, error) {
	if n, err := strconv.Atoi(value); err == nil {
		if n <= 0 || uint64(n) > maxProcessIdentity {
			return 0, fmt.Errorf("identity %q is not a non-root numeric ID", value)
		}
		return n, nil
	}
	groups, err := parseGroupFile("/etc/group")
	if err != nil {
		return 0, err
	}
	ids := groups[value]
	if len(ids) != 1 {
		return 0, fmt.Errorf("group %q is unresolved or ambiguous", value)
	}
	return ids[0], nil
}

func parsePasswdFile(path string) (map[string][2]int, error) {
	lines, err := boundedLines(path)
	if err != nil {
		return nil, err
	}
	entries := map[string][2]int{}
	byUID := map[int]int{}
	for _, line := range lines {
		if len(line) > maxAccountLineSize {
			return nil, fmt.Errorf("passwd entry in %s exceeds size limit", path)
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 || hasOversizedAccountField(fields) {
			continue
		}
		uid, e1 := strconv.Atoi(fields[2])
		gid, e2 := strconv.Atoi(fields[3])
		if e1 != nil || e2 != nil {
			continue
		}
		pair := [2]int{uid, gid}
		if _, exists := entries[fields[0]]; exists {
			return nil, fmt.Errorf("ambiguous passwd entry %q", fields[0])
		}
		entries[fields[0]] = pair
		byUID[uid]++
	}
	for _, pair := range entries {
		if byUID[pair[0]] > 1 {
			return nil, fmt.Errorf("ambiguous passwd UID %d", pair[0])
		}
	}
	return entries, nil
}

func parseGroupFile(path string) (map[string][]int, error) {
	lines, err := boundedLines(path)
	if err != nil {
		return nil, err
	}
	entries := map[string][]int{}
	for _, line := range lines {
		if len(line) > maxAccountLineSize {
			return nil, fmt.Errorf("group entry in %s exceeds size limit", path)
		}
		fields := strings.Split(line, ":")
		if len(fields) != 4 || hasOversizedAccountField(fields) {
			continue
		}
		gid, err := strconv.Atoi(fields[2])
		if err == nil {
			entries[fields[0]] = append(entries[fields[0]], gid)
		}
	}
	return entries, nil
}

func hasOversizedAccountField(fields []string) bool {
	for _, field := range fields {
		if len(field) > maxAccountFieldSize {
			return true
		}
	}
	return false
}

func boundedLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read account file %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxAccountFileSize {
		return nil, fmt.Errorf("account file %s exceeds size limit", path)
	}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), maxAccountFileSize)
	var out []string
	for s.Scan() {
		out = append(out, s.Text())
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

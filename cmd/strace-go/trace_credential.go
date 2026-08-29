package main

import (
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const invalidTraceCredentialID = ^uint32(0)

func prepareTraceTargetConfig(targets traceTargetConfig, effectiveUID int) (traceTargetConfig, error) {
	credential, err := resolveTraceCredential(targets.command.runAsUser, effectiveUID)
	if err != nil {
		return traceTargetConfig{}, err
	}
	targets.command.credential = credential
	return targets, nil
}

func applyTraceCommandCredential(cmd *exec.Cmd, credential *syscall.Credential) error {
	if credential == nil {
		return nil
	}
	if cmd == nil {
		return fmt.Errorf("trace command is nil")
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &unix.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = credential
	return nil
}

func resolveTraceCredential(value string, effectiveUID int) (*syscall.Credential, error) {
	if value == "" {
		return nil, nil
	}
	if effectiveUID != 0 {
		return nil, fmt.Errorf("You must be root to use the -u/--username option")
	}
	if credential, numeric, err := resolveNumericTraceCredential(value); numeric {
		return credential, err
	}
	account, err := user.Lookup(value)
	if err != nil {
		return nil, fmt.Errorf("Cannot find user %s", quoteTraceUserValue(value))
	}
	return traceCredentialFromUser(account)
}

func resolveNumericTraceCredential(value string) (*syscall.Credential, bool, error) {
	if !strings.Contains(value, ":") {
		return nil, false, nil
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return nil, true, invalidTraceUIDGIDError(value)
	}
	uid, err := parseTraceCredentialID(parts[0])
	if err != nil {
		return nil, true, invalidTraceUIDGIDError(value)
	}
	gid, err := parseTraceCredentialID(parts[1])
	if err != nil {
		return nil, true, invalidTraceUIDGIDError(value)
	}
	return &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}, true, nil
}

func invalidTraceUIDGIDError(value string) error {
	return fmt.Errorf("Invalid UID:GID pair %s", quoteTraceUserValue(value))
}

func quoteTraceUserValue(value string) string {
	quoted := strconv.QuoteToASCII(value)
	return "'" + quoted[1:len(quoted)-1] + "'"
}

func traceCredentialFromUser(account *user.User) (*syscall.Credential, error) {
	if account == nil {
		return nil, fmt.Errorf("resolved user is nil")
	}
	uid, err := parseTraceCredentialID(account.Uid)
	if err != nil {
		return nil, fmt.Errorf("invalid uid for user %q: %w", account.Username, err)
	}
	gid, err := parseTraceCredentialID(account.Gid)
	if err != nil {
		return nil, fmt.Errorf("invalid gid for user %q: %w", account.Username, err)
	}
	groups, err := traceSupplementaryGroups(account)
	if err != nil {
		return nil, err
	}
	return &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}, nil
}

func traceSupplementaryGroups(account *user.User) ([]uint32, error) {
	groupIDs, err := account.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("list groups for user %q: %w", account.Username, err)
	}
	groups := make([]uint32, 0, len(groupIDs))
	seen := make(map[uint32]bool, len(groupIDs))
	for _, groupID := range groupIDs {
		parsed, err := parseTraceCredentialID(groupID)
		if err != nil {
			return nil, fmt.Errorf("invalid supplementary gid for user %q: %w", account.Username, err)
		}
		if !seen[parsed] {
			seen[parsed] = true
			groups = append(groups, parsed)
		}
	}
	return groups, nil
}

func parseTraceCredentialID(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == uint64(invalidTraceCredentialID) {
		return 0, fmt.Errorf("invalid id %q", value)
	}
	return uint32(parsed), nil
}

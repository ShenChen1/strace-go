package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// traceAttachIdentity binds an attach request to the kernel task observed at
// bootstrap. It is closed before the event loop starts.
type traceAttachIdentity interface {
	exited() (bool, error)
	close() error
}

type traceAttachIdentityOpener interface {
	open(pid int) (traceAttachIdentity, error)
}

type pidfdAttachIdentityOpener struct{}

// PIDFD_THREAD binds the fd to the exact task, including a non-leader TID.
const pidfdThreadFlag = unix.O_EXCL

func (pidfdAttachIdentityOpener) open(pid int) (traceAttachIdentity, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("attach pid %d must be positive", pid)
	}
	fd, err := unix.PidfdOpen(pid, pidfdThreadFlag)
	if err != nil {
		return nil, fmt.Errorf("pidfd_open(%d): %w", pid, err)
	}
	return &pidfdAttachIdentity{fd: fd}, nil
}

type pidfdAttachIdentity struct {
	fd int
}

func (identity *pidfdAttachIdentity) exited() (bool, error) {
	if identity == nil || identity.fd < 0 {
		return false, errors.New("pidfd is closed")
	}
	fds := []unix.PollFd{{Fd: int32(identity.fd), Events: unix.POLLIN}}
	if _, err := unix.Poll(fds, 0); err != nil {
		return false, fmt.Errorf("poll pidfd: %w", err)
	}
	if fds[0].Revents&unix.POLLNVAL != 0 {
		return false, errors.New("poll pidfd: invalid descriptor")
	}
	return fds[0].Revents&(unix.POLLIN|unix.POLLERR|unix.POLLHUP) != 0, nil
}

func (identity *pidfdAttachIdentity) close() error {
	if identity == nil || identity.fd < 0 {
		return nil
	}
	fd := identity.fd
	identity.fd = -1
	return unix.Close(fd)
}

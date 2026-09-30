//go:build darwin

package main

import (
	"fmt"
	"net"
	"syscall"
)

// Values from <sys/un.h>; not exported by the syscall package.
const (
	solLocal     = 0
	localPeerPID = 0x002
)

// peerPID returns the process ID of the process on the other end of a Unix domain socket.
func peerPID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix socket: %T", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}

	var pid int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		pid, sockErr = syscall.GetsockoptInt(int(fd), solLocal, localPeerPID)
	}); err != nil {
		return 0, err
	}
	return pid, sockErr
}

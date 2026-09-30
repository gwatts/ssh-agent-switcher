//go:build !darwin

package main

import (
	"errors"
	"net"
)

func peerPID(conn net.Conn) (int, error) {
	return 0, errors.New("peer process detection not supported on this platform")
}

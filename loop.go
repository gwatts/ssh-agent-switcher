package main

// Loop detection for agent forwarding.
//
// When two machines each run ssh-agent-switcher and each has an "ssh -A" session open to the
// other, a request can bounce between them indefinitely: switcher A proxies to the agent
// forwarded from B, whose ssh client asks switcher B, which proxies to the agent forwarded from
// A, and so on.  Since OpenSSH 8.9 the ssh client blocks its whole connection while waiting for
// the reply to the session-bind message it sends when opening a forwarded agent channel, so such
// a loop hangs every session multiplexed over it.
//
// To break the loop, the switcher reads the first message of each connection.  If it is a
// session-bind for a forwarded channel, the client is a local ssh process relaying a request
// from the host it is connected to, and the switcher avoids any agent forwarded from that host.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

const (
	sshAgentcExtension   = 27
	sessionBindExtension = "session-bind@openssh.com"

	// maxAgentMsgLen mirrors the limit enforced by OpenSSH's ssh-agent.
	maxAgentMsgLen = 256 * 1024
)

// readAgentMessage reads a single SSH agent protocol message, returning the raw bytes including
// the length prefix.
func readAgentMessage(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxAgentMsgLen {
		return nil, fmt.Errorf("invalid agent message length %d", n)
	}

	msg := make([]byte, 4+n)
	copy(msg, hdr[:])
	if _, err := io.ReadFull(r, msg[4:]); err != nil {
		return nil, err
	}
	return msg, nil
}

// isForwardingBind reports whether msg is a session-bind@openssh.com extension request sent by
// an ssh client for a forwarded agent channel.
func isForwardingBind(msg []byte) bool {
	b := msg[4:]
	if len(b) == 0 || b[0] != sshAgentcExtension {
		return false
	}

	name, b, ok := readString(b[1:])
	if !ok || string(name) != sessionBindExtension {
		return false
	}
	// Skip the host key, session identifier and signature.
	for range 3 {
		if _, b, ok = readString(b); !ok {
			return false
		}
	}
	return len(b) > 0 && b[0] != 0
}

// readString decodes an SSH wire format string from the start of b.
func readString(b []byte) (s, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// clientOrigins returns the remote hosts that the process on the other end of client is
// connected to.  For an ssh client relaying a forwarded agent channel, that is the host the
// request came from.
func clientOrigins(client net.Conn) []netip.Addr {
	pid, err := peerPID(client)
	if err != nil {
		slog.Debug("failed to get client pid", slog.Any("error", err))
		return nil
	}
	addrs, err := remoteAddrs(pid)
	if err != nil {
		slog.Debug("failed to get client remote addresses", slog.Int("client_pid", pid), slog.Any("error", err))
		return nil
	}
	return addrs
}

// forwardedFrom reports whether the forwarded agent socket named name belongs to an sshd
// session connected to one of hosts.
func forwardedFrom(name string, hosts []netip.Addr) bool {
	if len(hosts) == 0 {
		return false
	}
	addrs, err := agentOrigins(name)
	if err != nil {
		slog.Debug("failed to get forwarded agent origins", slog.String("name", name), slog.Any("error", err))
		return false
	}
	return slices.ContainsFunc(addrs, func(a netip.Addr) bool {
		return slices.Contains(hosts, a)
	})
}

// agentOrigins returns the remote hosts of the sshd session that owns the forwarded agent
// socket named name, which sshd names "agent.<sshd pid>".
func agentOrigins(name string) ([]netip.Addr, error) {
	pid, err := strconv.Atoi(strings.TrimPrefix(name, "agent."))
	if err != nil {
		return nil, fmt.Errorf("unexpected agent socket name %q", name)
	}
	return remoteAddrs(pid)
}

// remoteAddrs returns the remote addresses of the established TCP connections held by process
// pid.
func remoteAddrs(pid int) ([]netip.Addr, error) {
	out, err := exec.Command("lsof", "-a", "-n", "-P", "-p", strconv.Itoa(pid),
		"-i", "TCP", "-s", "TCP:ESTABLISHED", "-F", "n").Output()
	if err != nil {
		// lsof exits with 1 when the process has no matching files.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("lsof failed: %v", err)
	}
	return parseLsofRemoteAddrs(string(out)), nil
}

// parseLsofRemoteAddrs extracts the remote addresses from "lsof -F n" output, whose TCP name
// lines look like "n192.0.2.1:61912->192.0.2.2:22".
func parseLsofRemoteAddrs(out string) []netip.Addr {
	var addrs []netip.Addr
	for _, line := range strings.Split(out, "\n") {
		name, ok := strings.CutPrefix(line, "n")
		if !ok {
			continue
		}
		_, remote, ok := strings.Cut(name, "->")
		if !ok {
			continue
		}
		ap, err := netip.ParseAddrPort(remote)
		if err != nil {
			continue
		}
		addrs = append(addrs, ap.Addr().Unmap())
	}
	// A process may hold the same connection on several descriptors.
	slices.SortFunc(addrs, netip.Addr.Compare)
	return slices.Compact(addrs)
}

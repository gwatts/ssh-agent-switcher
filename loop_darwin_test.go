//go:build darwin

package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestPeerPID(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	pid, err := peerPID(server)
	if err != nil {
		t.Fatalf("peerPID() failed: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("peerPID() = %d, want %d", pid, os.Getpid())
	}
}

// holdTCPConn keeps an established TCP connection to a loopback listener open for the duration
// of the test, and returns the loopback address.
func holdTCPConn(t *testing.T) netip.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	accepted, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { accepted.Close() })

	return netip.MustParseAddr("127.0.0.1")
}

func TestRemoteAddrs(t *testing.T) {
	loopback := holdTCPConn(t)

	addrs, err := remoteAddrs(os.Getpid())
	if err != nil {
		t.Fatalf("remoteAddrs() failed: %v", err)
	}
	if !slices.Contains(addrs, loopback) {
		t.Errorf("remoteAddrs() = %v, want it to contain %v", addrs, loopback)
	}
}

func TestFindAgentSocketAvoidsOrigin(t *testing.T) {
	loopback := holdTCPConn(t)

	// Name the socket after this process, which plays the role of the sshd session holding a
	// connection to the loopback "host".
	dir := shortTempDir(t)
	if err := os.Mkdir(filepath.Join(dir, "ssh-test"), 0700); err != nil {
		t.Fatal(err)
	}
	fakeAgent(t, filepath.Join(dir, "ssh-test", fmt.Sprintf("agent.%d", os.Getpid())), nil)

	if _, err := findAgentSocket(dir, []netip.Addr{loopback}); err == nil {
		t.Error("findAgentSocket() returned an agent forwarded from an avoided host")
	}

	agent, err := findAgentSocket(dir, []netip.Addr{netip.MustParseAddr("192.0.2.1")})
	if err != nil {
		t.Fatalf("findAgentSocket() failed: %v", err)
	}
	agent.Close()
}

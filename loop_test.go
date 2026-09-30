package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// agentMessage builds a length-prefixed agent message of the given type from SSH wire format
// fields: strings are length-prefixed and bools are single bytes.
func agentMessage(t *testing.T, msgType byte, fields ...any) []byte {
	t.Helper()
	body := []byte{msgType}
	for _, f := range fields {
		switch v := f.(type) {
		case string:
			body = binary.BigEndian.AppendUint32(body, uint32(len(v)))
			body = append(body, v...)
		case bool:
			if v {
				body = append(body, 1)
			} else {
				body = append(body, 0)
			}
		default:
			t.Fatalf("unsupported field type %T", f)
		}
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}

func TestIsForwardingBind(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
		want bool
	}{
		{"forwarding", agentMessage(t, sshAgentcExtension, sessionBindExtension, "hostkey", "sid", "sig", true), true},
		{"not forwarding", agentMessage(t, sshAgentcExtension, sessionBindExtension, "hostkey", "sid", "sig", false), false},
		{"other extension", agentMessage(t, sshAgentcExtension, "query", "hostkey", "sid", "sig", true), false},
		{"request identities", agentMessage(t, 11), false},
		{"truncated", agentMessage(t, sshAgentcExtension, sessionBindExtension, "hostkey", "sid"), false},
		{"missing flag", agentMessage(t, sshAgentcExtension, sessionBindExtension, "hostkey", "sid", "sig"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isForwardingBind(tt.msg); got != tt.want {
				t.Errorf("isForwardingBind() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadAgentMessage(t *testing.T) {
	first := agentMessage(t, 11)
	second := agentMessage(t, 13, "key", "data")
	r := bytes.NewReader(slices.Concat(first, second))

	got, err := readAgentMessage(r)
	if err != nil {
		t.Fatalf("readAgentMessage() failed: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Errorf("readAgentMessage() = %v, want %v", got, first)
	}

	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, second) {
		t.Errorf("readAgentMessage() consumed beyond the first message; remaining %v, want %v", rest, second)
	}
}

func TestReadAgentMessageInvalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"zero length", []byte{0, 0, 0, 0}},
		{"too long", binary.BigEndian.AppendUint32(nil, maxAgentMsgLen+1)},
		{"truncated", []byte{0, 0, 0, 5, 11}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := readAgentMessage(bytes.NewReader(tt.data)); err == nil {
				t.Error("readAgentMessage() succeeded, want error")
			}
		})
	}
}

func TestParseLsofRemoteAddrs(t *testing.T) {
	out := "p92812\nf4\nn100.89.14.21:61912->100.113.88.63:22\nf5\n" +
		"n[fd7a:115c:a1e0::1]:5000->[fd7a:115c:a1e0::2]:22\nf6\nn*:22\n" +
		"f7\nn100.89.14.21:61912->100.113.88.63:22\n"
	want := []netip.Addr{
		netip.MustParseAddr("100.113.88.63"),
		netip.MustParseAddr("fd7a:115c:a1e0::2"),
	}
	if got := parseLsofRemoteAddrs(out); !slices.Equal(got, want) {
		t.Errorf("parseLsofRemoteAddrs() = %v, want %v", got, want)
	}
}

// fakeAgent serves a unix socket at path that answers every request with reply.
func fakeAgent(t *testing.T, path string, reply []byte) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					if _, err := readAgentMessage(conn); err != nil {
						return
					}
					if _, err := conn.Write(reply); err != nil {
						return
					}
				}
			}()
		}
	}()
}

// shortTempDir returns a temporary directory under /tmp: the default temporary directory on
// macOS is too long for unix socket paths.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sas")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestHandleConnectionReplaysFirstRequest(t *testing.T) {
	dir := shortTempDir(t)
	if err := os.Mkdir(filepath.Join(dir, "ssh-test"), 0700); err != nil {
		t.Fatal(err)
	}
	reply := agentMessage(t, 12, "keys")
	fakeAgent(t, filepath.Join(dir, "ssh-test", "agent.1"), reply)

	oldAgentsDir := *agentsDir
	*agentsDir = dir
	t.Cleanup(func() { *agentsDir = oldAgentsDir })

	client, server := net.Pipe()
	defer client.Close()
	go handleConnection(server)

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := client.Write(agentMessage(t, 11)); err != nil {
			t.Fatal(err)
		}
		got, err := readAgentMessage(client)
		if err != nil {
			t.Fatalf("reading reply failed: %v", err)
		}
		if !bytes.Equal(got, reply) {
			t.Errorf("reply = %v, want %v", got, reply)
		}
	}
}

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// fakePeer serves body with the given status at /idle and returns the server's address.
func fakePeer(t *testing.T, status int, body string) netip.AddrPort {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/idle" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return netip.MustParseAddrPort(srv.Listener.Addr().String())
}

func TestPeerIdleTime(t *testing.T) {
	addr := fakePeer(t, http.StatusOK, "1m30s\n")

	got, err := peerIdleTime(addr)
	if err != nil {
		t.Fatalf("peerIdleTime() failed: %v", err)
	}
	if want := 90 * time.Second; got != want {
		t.Errorf("peerIdleTime() = %v, want %v", got, want)
	}
}

func TestPeerIdleTimeInvalid(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"server error", http.StatusInternalServerError, "not supported"},
		{"garbage", http.StatusOK, "soon"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := peerIdleTime(fakePeer(t, tt.status, tt.body)); err == nil {
				t.Error("peerIdleTime() succeeded, want error")
			}
		})
	}
}

func TestMinPeerIdleTime(t *testing.T) {
	addr := fakePeer(t, http.StatusOK, "5s")
	// The fake peer only listens on IPv4, so the IPv6 loopback is an unreachable peer.
	unreachable := netip.IPv6Loopback()

	got, err := minPeerIdleTime([]netip.Addr{unreachable, addr.Addr()}, int(addr.Port()))
	if err != nil {
		t.Fatalf("minPeerIdleTime() failed: %v", err)
	}
	if want := 5 * time.Second; got != want {
		t.Errorf("minPeerIdleTime() = %v, want %v", got, want)
	}

	if _, err := minPeerIdleTime([]netip.Addr{unreachable}, int(addr.Port())); err == nil {
		t.Error("minPeerIdleTime() with no reachable peers succeeded, want error")
	}
}

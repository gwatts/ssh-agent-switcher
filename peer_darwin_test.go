//go:build darwin

package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestHandlePeerIdle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(handlePeerIdle))
	defer srv.Close()

	got, err := peerIdleTime(netip.MustParseAddrPort(srv.Listener.Addr().String()))
	if err != nil {
		t.Fatalf("peerIdleTime() failed: %v", err)
	}
	want, err := getIdleTime()
	if err != nil {
		t.Fatal(err)
	}
	// Idle time only grows between the two readings, unless there is input in between.
	if got < 0 || got > want {
		t.Errorf("served idle time %v, want between 0 and %v", got, want)
	}
}

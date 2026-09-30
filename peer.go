package main

// Sharing idle time between switchers.
//
// Each switcher decides whether to prefer local agents by looking at how long the local
// keyboard/mouse has been idle.  With a fixed threshold, two machines that have both been idle
// for a while each conclude that the user is at the other one.  When -peer-port is set,
// switchers serve their idle time to each other so they can instead pick whichever machine had
// input most recently.

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

var peerClient = &http.Client{Timeout: 500 * time.Millisecond}

// servePeerIdle serves the local idle time to other switchers on the given port.
func servePeerIdle(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /idle", handlePeerIdle)
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	slog.Info("Serving idle time to peers", slog.Int("port", port))
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("Peer idle time server failed", slog.Any("error", err))
	}
}

func handlePeerIdle(w http.ResponseWriter, r *http.Request) {
	idle, err := getIdleTime()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, idle)
}

// peerIdleTime asks the switcher at addr for its local idle time.
func peerIdleTime(addr netip.AddrPort) (time.Duration, error) {
	resp, err := peerClient.Get("http://" + addr.String() + "/idle")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return time.ParseDuration(strings.TrimSpace(string(body)))
}

// minPeerIdleTime returns the shortest idle time reported by the switchers on hosts.
func minPeerIdleTime(hosts []netip.Addr, port int) (time.Duration, error) {
	var idle []time.Duration
	for _, host := range hosts {
		d, err := peerIdleTime(netip.AddrPortFrom(host, uint16(port)))
		if err != nil {
			slog.Info("Failed to get peer idle time", slog.Any("host", host), slog.Any("error", err))
			continue
		}
		idle = append(idle, d)
	}
	if len(idle) == 0 {
		return 0, errors.New("no peer reported its idle time")
	}
	return slices.Min(idle), nil
}

// forwardedOrigins returns the hosts that the agents forwarded by sshd under dir come from,
// excluding those in avoid.
func forwardedOrigins(dir string, avoid []netip.Addr) []netip.Addr {
	paths, err := filepath.Glob(filepath.Join(dir, "ssh-*", "agent.*"))
	if err != nil {
		return nil
	}

	var origins []netip.Addr
	for _, path := range paths {
		addrs, err := agentOrigins(filepath.Base(path))
		if err != nil {
			slog.Debug("failed to get forwarded agent origins", slog.String("path", path), slog.Any("error", err))
			continue
		}
		for _, addr := range addrs {
			if !slices.Contains(avoid, addr) && !slices.Contains(origins, addr) {
				origins = append(origins, addr)
			}
		}
	}
	return origins
}

// Copyright 2023 Julio Merino.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted
// provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this list of conditions
//   and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright notice, this list of
//   conditions and the following disclaimer in the documentation and/or other materials provided with
//   the distribution.
// * Neither the name of rules_shtk nor the names of its contributors may be used to endorse or
//   promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
// WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// ssh-agent-switcher serves a Unix domain socket that proxies connections to any valid SSH agent
// socket provided by sshd.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// if the keyboard/mouse has not been active on the local machine for longer than this
	// threshold, the machine is considered "idle" and switcher should prefer any remotely
	// connected agent instead.
	defaultIdleThreshold = 30 * time.Second

	// If the ssh-agent has not completed a response in this time limit, then the connection
	// is dropped.   This prevents processes being stuck in a  hung state as no-one was at the right
	// machine to approve the request.
	defaultConnTimeout = 10 * time.Second
)

var (
	socketPath    = flag.String("socket-path", defaultSocketPath(), "path to the socket to listen on")
	agentsDir     = flag.String("agents-dir", "/tmp", "directory where to look for running agents")
	idleThreshold = flag.Duration("idle-threshold", defaultIdleThreshold, "prefer local agents if local keyboard/mouse activity within idle time")
	connTimeout   = flag.Duration("conn-timeout", defaultConnTimeout, "Maximum time for an agent to approve a request")
	logFile       = flag.String("log-file", "", "Log filename to append to (defaults to stdout)")
	logLevel      = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
)

var (
	addtlAgents arrayFlags
	lf          *os.File = os.Stdout
)

func init() {
	flag.Var(&addtlAgents, "local-agent", "Additional local agent socket paths (can be repeated)")
}

type arrayFlags []string

// Implement the String method of the flag.Value interface.
func (i *arrayFlags) String() string {
	return strings.Join(*i, ", ")
}

// Implement the Set method of the flag.Value interface.
func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// parseLogLevel converts a string level to slog.Level
func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo // default to Info
	}
}

// defaultSocketPath computes the name of the default value for the socketPath flag.
func defaultSocketPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Sprintf("failed to get home dir: %v", err))
	}

	// Construct the full path
	socketDir := filepath.Join(homeDir, ".share", "ssh-agent-switcher")
	socketPath := filepath.Join(socketDir, "ssh-agent.sock")

	// Create directory if it doesn't exist
	if err = os.MkdirAll(socketDir, 0700); err != nil {
		panic(fmt.Sprintf("failed to create %s: %v", socketDir, err))
	}
	return socketPath
}

// findAgentSocketSubdir scans the contents of "dir", which should point to a session directory
// createdy by sshd, looks for a valid "agent.*" socket, opens it, and returns the connection to
// the agent.
//
// This tries all possible files in search for a socket and only returns an error if no valid
// and alive candidate can be found.
func findAgentSocketSubdir(dir string) (net.Conn, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())

		if !strings.HasPrefix(entry.Name(), "agent.") {
			slog.Debug("Ignoring filename that does not start with \"agent.\"", slog.String("path", path))
			continue
		}
		conn, err := checkSocket(path)
		if err == nil {
			return conn, nil
		}
		slog.Debug("skip file", slog.Any("reason", err))
	}
	return nil, errors.New("no socket in directory")
}

func checkSocket(path string) (net.Conn, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("Ignoring %s: stat failed: %v", path, err)
	}

	mode := fi.Sys().(*syscall.Stat_t).Mode
	if (mode & syscall.S_IFSOCK) == 0 {
		return nil, fmt.Errorf("Ignoring %s: not a socket", path)
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("Ignoring %s: open failed: %v", path, err)
	}

	slog.Info("Successfully opened SSH agent", slog.String("path", path))
	return conn, nil

}

// findAgentSocket scans the contents of "dir", which should point to the directory where
// sshd places the session directories for forwarded agents, looks for a valid connection to
// an agent, opens the agent's socket, and returns the connection to the agent.
//
// This tries all possible directories in search for a socket and only returns an error if
// no valid and alive candidate can be found.
func findAgentSocket(dir string) (net.Conn, error) {
	// It is tempting to use the *at family of system calls to avoid races when checking for
	// file metadata before opening the socket... but there is no guarantee that the sshd
	// instance will be present at all even after we open the socket, so the races don't
	// matter.  Also note that these checks are not meant to protect us against anything in
	// terms of security: they are merely to keep things speedy and nice.

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	// The sorting is unnecessary but it helps with testing certain conditions.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	ourUid := os.Getuid()
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())

		if !entry.IsDir() {
			slog.Debug("Ignoring: not a directory", slog.String("path", path))
			continue
		}

		if !strings.HasPrefix(entry.Name(), "ssh-") {
			slog.Debug("Ignoring: does not start with 'ssh-'", slog.String("path", path))
			continue
		}

		fi, err := os.Stat(path)
		if err != nil {
			slog.Debug("Ignoring: stat failed", slog.String("path", path), slog.Any("error", err))
			continue
		}

		// This check is not strictly necessary: if we found sshd sockets owned by other users, we
		// would simply fail to open them later anyway.
		uid := fi.Sys().(*syscall.Stat_t).Uid
		if int(uid) != ourUid {
			slog.Debug("Ignoring: owner %d is not current user %d",
				slog.String("path", path),
				slog.Int("file_uid", int(uid)), slog.Int("our_uid", int(ourUid)))
			continue
		}

		agent, err := findAgentSocketSubdir(path)
		if err != nil {
			slog.Debug("Ignoring path", slog.String("path", path), slog.Any("reason", err))
			continue
		}
		return agent, nil
	}

	return nil, errors.New("agent not found")
}

// proxyConnection forwards all request from the client to the agent, and all responses from
// the agent to the client.
func proxyConnection(client net.Conn, agent net.Conn) error {
	var wg sync.WaitGroup
	wg.Add(2)

	// Copy client → agent
	go func() {
		defer wg.Done()
		if _, err := io.Copy(agent, client); err != nil && !errors.Is(err, io.EOF) {
			slog.Warn("client→agent copy error", "error", err)
		}
	}()

	// Copy agent → client
	go func() {
		defer wg.Done()
		if _, err := io.Copy(client, agent); err != nil && !errors.Is(err, io.EOF) {
			slog.Warn("agent→client copy error", "error", err)
		}
	}()

	// Wait for either completion or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-time.After(*connTimeout):
		client.Close()
		agent.Close()
		return fmt.Errorf("connection timed out after 10 seconds")
	case <-done:
		return nil
	}
}

func isLocalActive() bool {
	idleTime, err := getIdleTime()
	if err != nil {
		slog.Debug("failed to get local user idle time", slog.Any("error", err))
		return false
	}
	isActive := idleTime < *idleThreshold
	slog.Info("detected local user idle status",
		slog.Bool("is_active", isActive),
		slog.Duration("idle_threshold", *idleThreshold),
		slog.Duration("current_idle_time", idleTime))
	return isActive
}

// handleConnection receives a connection from the client, looks for an sshd serving an agent,
// and proxies the connection to it.
func handleConnection(client net.Conn) {
	slog.Info("Accepted client connection")
	defer client.Close()

	var agent net.Conn
	var err error

	agent, err = findAgentSocket(*agentsDir)
	if err != nil {
		slog.Info("Dropping find connection", slog.Any("reason", err))
	}

	if agent == nil || isLocalActive() {
		for _, path := range addtlAgents {
			localAgent, err := checkSocket(path)
			if err == nil {
				agent = localAgent
				slog.Info("Using local agent")
				break
			}
			slog.Warn("Additional local socket check failed",
				slog.String("path", path), slog.Any("error", err))
		}
	}

	if agent == nil {
		return
	}

	defer agent.Close()

	if err := proxyConnection(client, agent); err != nil {
		slog.Info("Dropping proxy connection", slog.Any("error", err))
		return
	}
	slog.Info("Closing client connection")
}

func setupSignals(socketPath string, ln net.Listener) {
	c := make(chan os.Signal, 1)
	// Watch SIGHUP, SIGINT, and SIGTERM:
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for sig := range c {
			switch sig {
			case syscall.SIGHUP:
				slog.Info("Received SIGHUP: preparing for reload.")

				// First, get the current executable (which might be updated).
				exe, err := os.Executable()
				if err != nil {
					slog.Error("Unable to get current executable; skipping reload", "error", err)
					// If we can’t find our own executable, do NOT proceed to remove the socket.
					// We just log and continue running in the current process.
					continue
				}

				// Optionally, check that it exists and is executable.
				if st, err := os.Stat(exe); err != nil {
					slog.Error("Cannot stat current executable; skipping reload", "error", err)
					continue
				} else if st.Mode()&0111 == 0 {
					slog.Error("Executable bit not set on binary; skipping reload")
					continue
				}

				// If we get here, we can re-exec ourselves safely.
				slog.Info("Closing listener and removing socket before exec()",
					slog.String("socket_path", socketPath))
				ln.Close()
				os.Remove(socketPath)

				slog.Info("Exec", slog.String("exe", exe), slog.Any("args", os.Args))
				err = syscall.Exec(exe, os.Args, os.Environ())
				//err = errors.New("skip")
				// If Exec() fails, the process will continue here:
				if err != nil {
					slog.Error("Failed to re-exec process", "error", err)
					os.Exit(1)
				}

			case syscall.SIGINT, syscall.SIGTERM:
				slog.Info("Shutting down due to signal; removing socket",
					slog.String("socket_path", socketPath))
				ln.Close()
				os.Remove(socketPath)
				os.Exit(1)
			}
		}
	}()
}

func usage() {
	prog := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, `Usage: %s [flags]

ssh-agent-switcher serves a Unix domain socket that proxies connections to any valid SSH agent
socket provided by sshd. It automatically switches between local and remote SSH agents based
on system idle time.

Flags:
`, prog)
	flag.PrintDefaults()
	os.Exit(2)
}

func init() {
	flag.Usage = usage
}

func main() {
	flag.Parse()
	if len(flag.Args()) != 0 {
		fmt.Fprint(os.Stderr, "No arguments allowed")
		usage()
	}

	if *logFile != "" && *logFile != "-" {
		var err error
		lf, err = os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open logfile for write: %v", err)
		}
	}

	handler := slog.NewTextHandler(lf, &slog.HandlerOptions{
		// Set level from flag
		Level: parseLogLevel(*logLevel),
	})
	slog.SetDefault(slog.New(handler).With(slog.Int("pid", os.Getpid())))

	// Ensure the socket is not group nor world readable so that we don't expose the
	// real socket indirectly to other users.
	syscall.Umask(0177)
	socket, err := net.Listen("unix", *socketPath)
	if err != nil {
		slog.Error("Failed to bind to socket", slog.String("socket_path", *socketPath), slog.String("error", err.Error()))
		os.Exit(1)
	}
	slog.Info("Listening", slog.String("socket_path", *socketPath))

	setupSignals(*socketPath, socket)

	for {
		conn, err := socket.Accept()
		if errors.Is(err, net.ErrClosed) {
			slog.Info("Listener closed; waiting for syscall.Exec or exit.")
			select {} // block; signal handler will shutdown
		}
		if err != nil {
			slog.Error("Socket accept failed", slog.Any("error", err))
			os.Exit(1)
		}

		go handleConnection(conn)
	}
}

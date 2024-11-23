//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// getIdleTime returns the duration since the last HID (keyboard/mouse) input
func getIdleTime() (time.Duration, error) {
	cmd := exec.Command("ioreg", "-c", "IOHIDSystem")
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to run ioreg: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "HIDIdleTime") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				return 0, fmt.Errorf("unexpected ioreg output format")
			}

			nanoseconds, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("failed to parse idle time: %v", err)
			}

			return time.Duration(nanoseconds), nil
		}
	}

	return 0, fmt.Errorf("HIDIdleTime not found in ioreg output")
}

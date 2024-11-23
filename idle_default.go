//go:build !darwin

package main

import (
	"errors"
	"time"
)

func getIdleTime() (time.Duration, error) {
	return 0, errors.New("idle time detection not supported on this platform")
}

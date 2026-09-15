//go:build !darwin && !linux && !windows
// +build !darwin,!linux,!windows

package sshutil

import (
	"runtime"

	"github.com/sirupsen/logrus"
)

func detectAESAcceleration() bool {
	const fallback = runtime.GOARCH == "amd64"
	logrus.Warnf("cannot detect whether AES accelerator is available, assuming %v", fallback)
	return fallback
}

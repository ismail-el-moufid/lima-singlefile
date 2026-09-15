//go:build !darwin || !amd64 || !cgo

package main

import (
	"fmt"
	"os"
)

func runNative(_ string, _ []string) int {
	fmt.Fprintln(os.Stderr, "embedded QEMU requires a darwin/amd64 build with CGO and the native QEMU libraries linked")
	return 1
}

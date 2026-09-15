// Package embeddedassets holds the read-only assets shipped in the single-file Lima build.
package embeddedassets

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
)

//go:embed lima-guestagent.Linux-x86_64
var guestAgent []byte

//go:embed examples
var examples embed.FS

//go:embed LICENSE NOTES.md
var notices embed.FS

// CheckArch rejects architectures for which this bundle has no guest agent or QEMU.
func CheckArch(arch string) error {
	if arch != "x86_64" {
		return fmt.Errorf("single-file Lima supports only x86_64; architecture %q is unavailable in this bundle", arch)
	}
	return nil
}

// GuestAgent returns an independent reader without extracting an executable to disk.
func GuestAgent(arch string) (io.ReadCloser, error) {
	if err := CheckArch(arch); err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(guestAgent)), nil
}

func Templates() (fs.FS, error) {
	return fs.Sub(examples, "examples")
}

// Notices contains the Lima license and notes about the embedded assets.
func Notices() fs.FS {
	return notices
}

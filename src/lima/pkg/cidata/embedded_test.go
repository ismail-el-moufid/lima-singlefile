package cidata

import (
	"io"
	"strings"
	"testing"

	"github.com/lima-vm/lima/pkg/limayaml"
)

func TestGuestAgentBinaryEmbedded(t *testing.T) {
	reader, err := GuestAgentBinary(limayaml.X8664)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var magic [4]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil {
		t.Fatal(err)
	}
	if string(magic[:]) != "\x7fELF" {
		t.Fatalf("not a Linux ELF: %q", magic)
	}
	if _, err := GuestAgentBinary(limayaml.AARCH64); err == nil {
		t.Fatal("accepted unavailable agent")
	}
}

func TestISORejectsArchitectureBeforeStorage(t *testing.T) {
	arch := limayaml.AARCH64
	y := &limayaml.LimaYAML{Arch: &arch}
	if err := GenerateISO9660(t.TempDir(), "unsupported", y, 0, 0, ""); err == nil || !strings.Contains(err.Error(), "only x86_64") {
		t.Fatalf("expected architecture error before ISO preparation, got %v", err)
	}
}

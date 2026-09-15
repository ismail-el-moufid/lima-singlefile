package embeddedassets

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"testing"
)

func TestGuestAgentBytes(t *testing.T) {
	for i := 0; i < 2; i++ {
		reader, err := GuestAgent("x86_64")
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != 7135232 || string(data[:4]) != "\x7fELF" {
			t.Fatalf("unexpected guest agent: %d bytes", len(data))
		}
		const want = "b10989ec96ac40392b4d49494577fe308de8d6e734c5024722be82cdd29c464c"
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
			t.Fatalf("guest agent digest = %s, want %s", got, want)
		}
	}
}

func TestUnavailableArchitectures(t *testing.T) {
	for _, arch := range []string{"", "amd64", "aarch64", "riscv64"} {
		if r, err := GuestAgent(arch); err == nil || r != nil {
			t.Fatalf("GuestAgent(%q) = %v, %v", arch, r, err)
		}
	}
}

func TestEmbeddedNotices(t *testing.T) {
	for _, name := range []string{"LICENSE", "NOTES.md"} {
		data, err := fs.ReadFile(Notices(), name)
		if err != nil || len(data) == 0 {
			t.Fatalf("notice %s: %v", name, err)
		}
	}
	examples, err := Templates()
	if err != nil {
		t.Fatal(err)
	}
	if data, err := fs.ReadFile(examples, "README.md"); err != nil || len(data) == 0 {
		t.Fatalf("template notes: %v", err)
	}
}

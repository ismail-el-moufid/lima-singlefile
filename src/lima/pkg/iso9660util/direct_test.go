package iso9660util

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diskfs/go-diskfs/filesystem/iso9660"
	"github.com/lima-vm/lima/pkg/embeddedassets"
)

func TestDirectISOEmbeddedGuestAgent(t *testing.T) {
	dir := t.TempDir()
	// Even an unusable temporary directory must not prevent ISO generation.
	blocked := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocked, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, env := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(env, blocked)
	}
	agent, err := embeddedassets.GuestAgent("x86_64")
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	layout := []Entry{{Path: "lima-guestagent", Reader: agent}}
	contents := map[string]string{
		"meta-data":                  "instance-id: test\n",
		"user-data":                  "#cloud-config\n",
		"boot/25-guestagent-base.sh": "#!/bin/sh\n",
		"provision.system/00000001":  "echo provision\n",
		"nested/Mixed Case/" + strings.Repeat("long-name", 12): "long name\n",
		"empty": "",
	}
	// Exercise directory records that cannot fit within a single sector.
	for i := 0; i < 50; i++ {
		contents[fmt.Sprintf("boot/%03d.sh", i)] = fmt.Sprintf("echo %d\n", i)
	}
	for name, content := range contents {
		layout = append(layout, Entry{Path: name, Reader: strings.NewReader(content)})
	}
	isoPath := filepath.Join(dir, "cidata.iso")
	if err := Write(isoPath, "cidata", layout); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("unexpected staging files: %v, %v", entries, err)
	}
	isoFile, err := os.Open(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	defer isoFile.Close()
	stat, err := isoFile.Stat()
	if err != nil {
		t.Fatal(err)
	}
	image, err := iso9660.Read(isoFile, stat.Size(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimRight(image.Label(), " ") != "cidata" {
		t.Fatalf("volume label = %q", image.Label())
	}
	read := func(name string) []byte {
		t.Helper()
		f, err := image.OpenFile("/"+name, os.O_RDONLY)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		b, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, want := range contents {
		if got := string(read(name)); got != want {
			t.Fatalf("ISO %q = %q, want %q", name, got, want)
		}
	}
	const wantHash = "b10989ec96ac40392b4d49494577fe308de8d6e734c5024722be82cdd29c464c"
	if got := fmt.Sprintf("%x", sha256.Sum256(read("lima-guestagent"))); got != wantHash {
		t.Fatalf("guest agent hash in ISO = %s", got)
	}
	if ok, err := IsISO9660(isoPath); err != nil || !ok {
		t.Fatalf("ISO detection = %v, %v", ok, err)
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestDirectISOReaderError(t *testing.T) {
	want := errors.New("input asset failed")
	isoPath := filepath.Join(t.TempDir(), "cidata.iso")
	err := Write(isoPath, "cidata", []Entry{{Path: "lima-guestagent", Reader: failingReader{want}}})
	if !errors.Is(err, want) {
		t.Fatalf("reader error = %v", err)
	}
	if _, err := os.Stat(isoPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("incomplete ISO remains: %v", err)
	}
}

func TestDirectISOInvalidLayout(t *testing.T) {
	for _, name := range []string{"", ".", "../escape", "/absolute", "bad\x00name", strings.Repeat("n", 129), "a/b/c/d/e/f/g/h/i"} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			_, _, _, err := isoTree([]Entry{{Path: name, Reader: bytes.NewReader(nil)}})
			if err == nil {
				t.Fatalf("accepted path %q", name)
			}
		})
	}
	for _, names := range [][]string{{"same", "same"}, {"file", "file/child"}, {"dir/child", "dir"}} {
		var layout []Entry
		for _, name := range names {
			layout = append(layout, Entry{Path: name, Reader: bytes.NewReader(nil)})
		}
		if _, _, _, err := isoTree(layout); err == nil {
			t.Fatalf("accepted conflicting paths %q", names)
		}
	}
}

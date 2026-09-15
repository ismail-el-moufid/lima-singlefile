package imgutil

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestGetInfoWorkerPrefixAndJSON(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LIMA_TEST_IMG_WORKER", "1")
	t.Setenv("QEMU_IMG", strconv.Quote(self)+" -test.run=^TestImageWorker$ -- --internal-qemu-img")
	info, err := GetInfo("disk with spaces")
	if err != nil {
		t.Fatal(err)
	}
	if info.Format != "qcow2" {
		t.Fatalf("format = %q", info.Format)
	}
}

func TestImageWorker(t *testing.T) {
	if os.Getenv("LIMA_TEST_IMG_WORKER") != "1" {
		return
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if strings.Join(args, "|") != "--internal-qemu-img|info|--output=json|disk with spaces" {
		os.Exit(93)
	}
	fmt.Fprintln(os.Stderr, "diagnostics stay out of JSON")
	fmt.Fprintln(os.Stdout, `{"format":"qcow2"}`)
	os.Exit(0)
}

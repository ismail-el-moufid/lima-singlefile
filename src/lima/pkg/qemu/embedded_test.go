package qemu

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lima-vm/lima/pkg/limayaml"
	"github.com/lima-vm/lima/pkg/qemu/command"
)

func TestBundledFirmwareURI(t *testing.T) {
	firmware, err := firmwareForCommand("/nonexistent/limactl", []string{command.QEMU}, limayaml.X8664)
	if err != nil || firmware != "builtin:edk2-x86_64-code.fd" {
		t.Fatalf("firmware = %q, %v", firmware, err)
	}
	if _, err := firmwareForCommand("/nonexistent/limactl", []string{command.QEMU}, limayaml.AARCH64); err == nil {
		t.Fatal("accepted unavailable bundled firmware")
	}
}

func TestExternalFirmwareLookup(t *testing.T) {
	prefix := t.TempDir()
	firmware := filepath.Join(prefix, "share", "qemu", "edk2-x86_64-code.fd")
	if err := os.MkdirAll(filepath.Dir(firmware), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firmware, nil, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := firmwareForCommand(filepath.Join(prefix, "bin", "qemu-system-x86_64"), nil, limayaml.X8664)
	// A user-local firmware can legitimately take precedence over the executable prefix.
	if err != nil || strings.HasPrefix(got, "builtin:") {
		t.Fatalf("external firmware = %q, %v", got, err)
	}
	if _, err := os.Stat(got); err != nil {
		t.Fatal(err)
	}
}

func TestFeatureProbePrefixes(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LIMA_TEST_FEATURE_WORKER", "1")
	for _, stderr := range []string{"0", "1"} {
		t.Setenv("LIMA_TEST_FEATURE_STDERR", stderr)
		f, err := inspectFeatures(self, []string{"-test.run=^TestFeatureWorker$", "--", command.QEMU})
		if err != nil {
			t.Fatal(err)
		}
		if string(f.AccelHelp) != "hvf tcg\n" || string(f.NetdevHelp) != "user socket\n" || string(f.MachineHelp) != "pc-q35-7.0\n" || !f.VersionGEQ7 {
			t.Fatalf("mixed or missing capability output: %+v", f)
		}
	}
}

func TestFeatureWorker(t *testing.T) {
	if os.Getenv("LIMA_TEST_FEATURE_WORKER") != "1" {
		return
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 || args[0] != command.QEMU {
		os.Exit(91)
	}
	output := os.Stdout
	if os.Getenv("LIMA_TEST_FEATURE_STDERR") == "1" {
		output = os.Stderr
	}
	switch strings.Join(args[1:], " ") {
	case "-M none -accel help":
		fmt.Fprintln(output, "hvf tcg")
	case "-M none -netdev help":
		fmt.Fprintln(output, "user socket")
	case "-machine help":
		fmt.Fprintln(output, "pc-q35-7.0")
	default:
		os.Exit(92)
	}
	os.Exit(0)
}

func TestEnsureDiskRejectsUnavailableArch(t *testing.T) {
	arch := limayaml.AARCH64
	err := EnsureDisk(Config{LimaYAML: &limayaml.LimaYAML{Arch: &arch}})
	if err == nil || !strings.Contains(err.Error(), "only x86_64") {
		t.Fatalf("architecture error: %v", err)
	}
}

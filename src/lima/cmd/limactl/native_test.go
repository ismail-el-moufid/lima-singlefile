package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lima-vm/lima/pkg/qemu/command"
	"github.com/lima-vm/lima/pkg/store/dirnames"
)

func TestInternalFlagRejection(t *testing.T) {
	for _, args := range [][]string{
		{"-daemonize"}, {"--daemonize"}, {"-daemonize=yes"},
		{"-mem-prealloc"}, {"--mem-prealloc"}, {"-mem-prealloc=on"},
		{"-object", "memory-backend-ram,id=ram0,size=1G,prealloc=on"},
		{"-object", `{"qom-type":"memory-backend-ram","id":"ram0","prealloc": true}`},
		{"-object", "memory-backend-file,prealloc=yes"},
		{"-object", "memory-backend-ram,prealloc=1"},
		{"-object", "memory-backend-ram,id=ram0,prealloc"},
		{"-object", "memory-backend-ram,prealloc,id=ram0"},
		{"-global", "memory-backend-ram.prealloc=on"},
		{"-object", `{"qom-type":"memory-backend-ram","prealloc":"on"}`},
		{"bad\x00argument"},
	} {
		for _, mode := range []string{command.QEMU, command.QEMUImg} {
			var stderr bytes.Buffer
			handled, code := dispatchInternal(append([]string{mode}, args...), &stderr, func(string, []string) int {
				t.Fatalf("native entry reached for forbidden arguments %q", args)
				return 0
			})
			if !handled || code == 0 || stderr.Len() == 0 {
				t.Fatalf("guard %q: %v, %d, %q", args, handled, code, stderr.String())
			}
		}
	}
	for _, args := range [][]string{
		{"-machine", "help"}, {"info", "--output=json", "disk"},
		{"-object", "memory-backend-ram,id=ram0,prealloc=off"},
		{"-object", "memory-backend-ram,id=ram0,prealloc=no"},
		{"-object", "memory-backend-ram,id=ram0,prealloc=0"},
		{"-global", "memory-backend-ram.prealloc=off"},
		{"-object", `{"qom-type":"memory-backend-ram","prealloc":false}`},
		{"create", "-o", "preallocation=metadata", "disk"},
	} {
		if err := validateInternalArgs(args); err != nil {
			t.Fatalf("rejected valid %q: %v", args, err)
		}
	}
}

func TestInternalDispatchIgnoresStorage(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LIMA_HOME", "")
	dirnames.SetHomePromptEnabled(true)
	t.Cleanup(func() { dirnames.SetHomePromptEnabled(false) })
	configDir := filepath.Join(home, "goinfre")
	if err := os.Mkdir(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(configDir, "lima-config.json")
	if err := os.WriteFile(config, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.CreateTemp(home, "stdin-")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err := input.WriteString("must not consume\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	previous := os.Stdin
	os.Stdin = input
	t.Cleanup(func() { os.Stdin = previous })
	for _, mode := range []string{command.QEMU, command.QEMUImg} {
		var stderr bytes.Buffer
		called := false
		handled, code := dispatchInternal([]string{mode, "--help"}, &stderr, func(gotMode string, args []string) int {
			called = true
			if gotMode != mode || !reflect.DeepEqual(args, []string{"--help"}) {
				t.Fatalf("dispatch: %s %q", gotMode, args)
			}
			return 23
		})
		if !handled || code != 23 || !called || stderr.Len() != 0 {
			t.Fatalf("dispatch = %v, %d, %q", handled, code, stderr.String())
		}
	}
	if offset, err := input.Seek(0, io.SeekCurrent); err != nil || offset != 0 {
		t.Fatalf("worker consumed stdin: %d, %v", offset, err)
	}
	if data, err := os.ReadFile(config); err != nil || string(data) != "{" {
		t.Fatalf("worker changed settings: %q, %v", data, err)
	}
}

func TestOrdinaryArgumentsDoNotDispatch(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"--version"}, {"start", "--internal-qemu"}} {
		handled, _ := dispatchInternal(args, io.Discard, func(string, []string) int { t.Fatal("unexpected dispatch"); return 0 })
		if handled {
			t.Fatalf("handled ordinary arguments %q", args)
		}
	}
}

func TestMetadataCommandsDoNotNeedStorage(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("LIMA_HOME", "")
	for _, arg := range []string{"--help", "--version", "licenses"} {
		cmd := newApp()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SetArgs([]string{arg})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%s: %v", arg, err)
		}
		if output.Len() == 0 || strings.Contains(output.String(), "Lima storage directory [") {
			t.Fatalf("%s output: %q", arg, output.String())
		}
	}
}

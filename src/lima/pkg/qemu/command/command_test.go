package command

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestBundledCommandsWithoutPATH(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("QEMU_SYSTEM_X86_64", "")
	t.Setenv("QEMU_IMG", "")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, prefix, err := System("x86_64")
	if err != nil || exe != self || !reflect.DeepEqual(prefix, []string{QEMU}) {
		t.Fatalf("System = %q %q, %v", exe, prefix, err)
	}
	cmd := New(exe, prefix, "-machine", "help")
	if want := []string{self, QEMU, "-machine", "help"}; !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("probe args = %q, want %q", cmd.Args, want)
	}
	image, err := ImageCmd("info", "--output=json", "disk")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{self, QEMUImg, "info", "--output=json", "disk"}; !reflect.DeepEqual(image.Args, want) {
		t.Fatalf("image args = %q, want %q", image.Args, want)
	}
	if !reflect.DeepEqual(prefix, []string{QEMU}) {
		t.Fatal("prefix mutated")
	}
}

func TestExternalOverrides(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range []string{"QEMU_SYSTEM_X86_64", "QEMU_IMG"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, strconv.Quote(self)+" --marker 'two words'")
			var exe string
			var prefix []string
			var err error
			if env == "QEMU_IMG" {
				exe, prefix, err = Image()
			} else {
				exe, prefix, err = System("x86_64")
			}
			if err != nil || exe != self || !reflect.DeepEqual(prefix, []string{"--marker", "two words"}) {
				t.Fatalf("override = %q %q, %v", exe, prefix, err)
			}
			if IsBundledSystem(prefix) {
				t.Fatal("external command treated as bundled")
			}
		})
	}
}

func TestInvalidOverridesAndArchitectures(t *testing.T) {
	for _, value := range []string{" ", "''", "'unterminated"} {
		t.Setenv("QEMU_SYSTEM_X86_64", value)
		if _, _, err := System("x86_64"); err == nil {
			t.Fatalf("accepted %q", value)
		}
		t.Setenv("QEMU_IMG", value)
		if _, _, err := Image(); err == nil {
			t.Fatalf("accepted image override %q", value)
		}
	}
	for _, arch := range []string{"", "aarch64", "riscv64"} {
		if _, _, err := System(arch); err == nil || !strings.Contains(err.Error(), "only x86_64") {
			t.Fatalf("System(%q): %v", arch, err)
		}
	}
}

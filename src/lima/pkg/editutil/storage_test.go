package editutil

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lima-vm/lima/pkg/store/dirnames"
	"github.com/lima-vm/lima/pkg/store/filenames"
)

func storageInput(t *testing.T, text string) {
	t.Helper()
	input, err := os.CreateTemp(t.TempDir(), "input-")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	previous := os.Stdin
	os.Stdin = input
	dirnames.SetHomePromptEnabled(true)
	t.Cleanup(func() {
		dirnames.SetHomePromptEnabled(false)
		os.Stdin = previous
		input.Close()
	})
}

func TestEditorHeaderPropagatesStorageCancellation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LIMA_HOME", "")
	storageInput(t, "")
	header, err := GenerateEditorWarningHeader()
	if header != "" || !errors.Is(err, io.EOF) {
		t.Fatalf("header = %q, error = %v; want empty header and EOF", header, err)
	}
	if _, err := os.Stat(filepath.Join(home, "goinfre", "lima-config.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled setup saved a setting: %v", err)
	}
}

func TestEditorHeaderPropagatesInvalidStorageSettings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LIMA_HOME", "")
	configDir := filepath.Join(home, "goinfre")
	if err := os.Mkdir(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "lima-config.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	header, err := GenerateEditorWarningHeader()
	if header != "" || err == nil || !strings.Contains(err.Error(), "read Lima storage setting") {
		t.Fatalf("header = %q, error = %v; want settings error", header, err)
	}
}

func TestEditorHeaderPropagatesStorageSaveFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LIMA_HOME", "")
	configDir := filepath.Join(home, "goinfre")
	if err := os.Mkdir(configDir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(configDir, 0700) })
	storageInput(t, filepath.Join(home, "custom-vms")+"\n")
	header, err := GenerateEditorWarningHeader()
	if header != "" || err == nil || !strings.Contains(err.Error(), "save Lima storage setting") {
		t.Fatalf("header = %q, error = %v; want persistence error", header, err)
	}
}

func TestEditorHeaderPreservesWarnings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("LIMA_HOME", home)
	configDir := filepath.Join(home, filenames.ConfigDir)
	if err := os.Mkdir(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{filenames.Default: "cpus: 2\n", filenames.Override: "memory: 1GiB\n"} {
		if err := os.WriteFile(filepath.Join(configDir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	header, err := GenerateEditorWarningHeader()
	if err != nil || !strings.Contains(header, "# cpus: 2") || !strings.Contains(header, "# memory: 1GiB") {
		t.Fatalf("header = %q, error = %v; want default and override warnings", header, err)
	}
}

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lima-vm/lima/pkg/store/dirnames"
)

func TestListTemplatesIgnoresBrokenStorage(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("CLI refuses to run as root")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LIMA_HOME", "")
	dirnames.SetHomePromptEnabled(false)
	t.Cleanup(func() { dirnames.SetHomePromptEnabled(false) })
	configDir := filepath.Join(home, "goinfre")
	if err := os.Mkdir(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "lima-config.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	app := newApp()
	app.SetOut(&output)
	app.SetErr(&output)
	app.SetArgs([]string{"start", "--list-templates"})
	if err := app.Execute(); err != nil {
		t.Fatal(err)
	}
	names := strings.Fields(output.String())
	if len(names) != 38 || !sort.StringsAreSorted(names) {
		t.Fatalf("unexpected templates: %q", output.String())
	}
	if _, err := os.Stat(filepath.Join(configDir, "lima-home")); !os.IsNotExist(err) {
		t.Fatalf("template listing touched instance storage: %v", err)
	}
}

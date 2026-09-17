package templatestore

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lima-vm/lima/pkg/store/dirnames"
)

func TestEmbeddedTemplatesWithoutStorage(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LIMA_HOME", "")
	dirnames.SetHomePromptEnabled(true)
	t.Cleanup(func() { dirnames.SetHomePromptEnabled(false) })
	templates, err := Templates()
	if err != nil {
		t.Fatal(err)
	}
	if len(templates) != 38 {
		t.Fatalf("got %d templates, want 38", len(templates))
	}
	found := map[string]bool{}
	previous := ""
	for _, template := range templates {
		if template.Name <= previous {
			t.Fatalf("templates not sorted: %q", template.Name)
		}
		previous = template.Name
		found[template.Name] = true
		if template.Location != "template://"+template.Name {
			t.Fatalf("unexpected location: %s", template.Location)
		}
		data, err := Read(template.Name)
		if err != nil || len(data) == 0 {
			t.Fatalf("Read(%q): %v", template.Name, err)
		}
	}
	for _, name := range []string{Default, "ubuntu", "debian", "alpine-docker", "deprecated/centos-7"} {
		if !found[name] {
			t.Errorf("missing template %q", name)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "goinfre")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("template access touched storage: %v", err)
	}
}

func TestTemplateNamesCannotEscapeFS(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../default", "/default", "deprecated/../../default"} {
		if _, err := Read(name); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("Read(%q) = %v, want invalid path", name, err)
		}
	}
	if _, err := Read("no-such-template"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing template error: %v", err)
	}
}

func TestTemplatesIgnoreBrokenSettings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LIMA_HOME", "")
	config := filepath.Join(home, "goinfre")
	if err := os.Mkdir(config, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config, "lima-config.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := Read(Default)
	if err != nil || !strings.Contains(string(data), "images:") {
		t.Fatalf("default template: %v", err)
	}
}

package downloader

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lima-vm/lima/pkg/store/dirnames"
)

func TestCacheFollowsStorage(t *testing.T) {
	dirnames.SetHomePromptEnabled(false)
	for _, scenario := range []string{"default", "saved", "explicit", "corrupt"} {
		t.Run(scenario, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("LIMA_HOME", "")
			t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "not-lima"))
			want := filepath.Join(home, "goinfre", "lima-home", "_cache")
			if scenario != "default" {
				configDir := filepath.Join(home, "goinfre")
				if err := os.Mkdir(configDir, 0700); err != nil {
					t.Fatal(err)
				}
				data := []byte("{")
				if scenario == "saved" {
					selected := filepath.Join(home, "selected")
					data, _ = json.Marshal(map[string]string{"home": selected})
					want = filepath.Join(selected, "_cache")
				}
				if err := os.WriteFile(filepath.Join(configDir, "lima-config.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "explicit" {
				selected := filepath.Join(home, "explicit")
				t.Setenv("LIMA_HOME", selected)
				want = filepath.Join(selected, "_cache")
			}
			got, err := CacheDir()
			if scenario == "corrupt" {
				if err == nil || !strings.Contains(err.Error(), "storage setting") {
					t.Fatalf("lost storage error: %v", err)
				}
				return
			}
			if err != nil || got != want {
				t.Fatalf("cache = %q, %v; want %q", got, err, want)
			}
			var opts options
			if err := WithCache()(&opts); err != nil || opts.cacheDir != want {
				t.Fatalf("cache option: %+v, %v", opts, err)
			}
			if _, err := os.Stat(want); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("lookup created cache: %v", err)
			}
			if scenario == "default" {
				if _, err := os.Stat(filepath.Join(home, "goinfre")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("lookup saved settings: %v", err)
				}
			}
		})
	}
}

func TestExplicitCacheDirDoesNotResolveHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("LIMA_HOME", "")
	dirnames.SetHomePromptEnabled(true)
	t.Cleanup(func() { dirnames.SetHomePromptEnabled(false) })
	var opts options
	for _, dir := range []string{t.TempDir(), ""} {
		if err := WithCacheDir(dir)(&opts); err != nil || opts.cacheDir != dir {
			t.Fatalf("explicit cache = %q, %v", opts.cacheDir, err)
		}
	}
}

func TestCachePropagatesStorageCancellation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LIMA_HOME", "")
	input, err := os.CreateTemp(home, "stdin-")
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.CreateTemp(home, "stderr-")
	if err != nil {
		t.Fatal(err)
	}
	previousInput, previousOutput := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = input, output
	dirnames.SetHomePromptEnabled(true)
	t.Cleanup(func() {
		os.Stdin, os.Stderr = previousInput, previousOutput
		dirnames.SetHomePromptEnabled(false)
		input.Close()
		output.Close()
	})
	if dir, err := CacheDir(); dir != "" || !errors.Is(err, io.EOF) {
		t.Fatalf("cache cancellation = %q, %v", dir, err)
	}
	if _, err := os.Stat(filepath.Join(home, "goinfre")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled cache lookup saved settings: %v", err)
	}
}

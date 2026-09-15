package dirnames

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const storagePrompt = "Lima storage directory [~/goinfre/lima-home]: "

func storageConfigPath(home string) string {
	return filepath.Join(home, "goinfre", "lima-config.json")
}

func assertStorageAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lstat(%q) = %v, want not exist", path, err)
	}
}

func writeStorageConfig(t *testing.T, home, data string) {
	t.Helper()
	path := storageConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func writeSavedStorageHome(t *testing.T, home, dir string) {
	t.Helper()
	data, err := json.Marshal(map[string]string{"home": dir})
	if err != nil {
		t.Fatal(err)
	}
	writeStorageConfig(t, home, string(data))
}

func assertSavedStorageHome(t *testing.T, home, want string) []byte {
	t.Helper()
	path := storageConfigPath(home)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]string
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("invalid saved JSON: %v", err)
	}
	if len(settings) != 1 || settings["home"] != want {
		t.Fatalf("saved settings = %v, want only home=%q", settings, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".lima-config-") {
			t.Errorf("temporary config was not removed: %s", entry.Name())
		}
	}
	return data
}

type unexpectedStorageInput struct{ t *testing.T }

func (r unexpectedStorageInput) Read([]byte) (int, error) {
	r.t.Error("saved storage lookup unexpectedly read prompt input")
	return 0, io.EOF
}

func disableStoragePrompt(t *testing.T) {
	t.Helper()
	previous := homePromptEnabled.Load()
	SetHomePromptEnabled(false)
	t.Cleanup(func() { SetHomePromptEnabled(previous) })
}

func TestStoragePromptDisabledByDefault(t *testing.T) {
	if homePromptEnabled.Load() {
		t.Fatal("home prompt must default to disabled")
	}
	t.Cleanup(func() { SetHomePromptEnabled(false) })
	SetHomePromptEnabled(true)
	if !homePromptEnabled.Load() {
		t.Fatal("SetHomePromptEnabled(true) did not enable prompting")
	}
	SetHomePromptEnabled(false)
	if homePromptEnabled.Load() {
		t.Fatal("SetHomePromptEnabled(false) did not disable prompting")
	}
}

func TestResolveHomeNoninteractiveDefault(t *testing.T) {
	home := t.TempDir()
	want := filepath.Join(home, "goinfre", "lima-home")
	var output bytes.Buffer
	for _, writer := range []io.Writer{nil, &output} {
		got, err := resolveHome(home, nil, writer)
		if err != nil || got != want {
			t.Fatalf("resolveHome() = %q, %v; want %q, nil", got, err, want)
		}
	}
	if output.Len() != 0 {
		t.Fatalf("noninteractive output = %q", output.String())
	}
	assertStorageAbsent(t, filepath.Join(home, "goinfre"))
}

func TestResolveHomePromptSavesOnce(t *testing.T) {
	for _, choice := range []string{"default", "absolute", "tilde"} {
		t.Run(choice, func(t *testing.T) {
			home := t.TempDir()
			want := filepath.Join(home, "goinfre", "lima-home")
			answer := ""
			switch choice {
			case "absolute":
				want = filepath.Join(home, "custom", "lima home")
				answer = want
			case "tilde":
				want = filepath.Join(home, "custom", "lima home")
				answer = "~/custom/lima home"
			}
			var output bytes.Buffer
			got, err := resolveHome(home, strings.NewReader(answer+"\n"), &output)
			if err != nil || got != want {
				t.Fatalf("resolveHome() = %q, %v; want %q, nil", got, err, want)
			}
			if count := strings.Count(output.String(), storagePrompt); count != 1 {
				t.Fatalf("prompt count = %d, want 1; output: %q", count, output.String())
			}
			entries, err := os.ReadDir(want)
			if err != nil {
				t.Fatalf("chosen directory was not created: %v", err)
			}
			if len(entries) != 0 {
				t.Fatalf("chosen directory contains leftover write probes: %v", entries)
			}
			before := assertSavedStorageHome(t, home, want)
			for _, input := range []io.Reader{nil, unexpectedStorageInput{t}} {
				output.Reset()
				got, err = resolveHome(home, input, &output)
				if err != nil || got != want {
					t.Fatalf("saved lookup = %q, %v; want %q, nil", got, err, want)
				}
				if output.Len() != 0 {
					t.Fatalf("saved lookup produced output: %q", output.String())
				}
				if after := assertSavedStorageHome(t, home, want); !bytes.Equal(before, after) {
					t.Fatal("saved lookup changed configuration")
				}
			}
		})
	}
}

func TestResolveHomeInvalidInputRetries(t *testing.T) {
	for _, kind := range []string{"relative", "file", "control"} {
		t.Run(kind, func(t *testing.T) {
			home := t.TempDir()
			invalid := "relative/lima-home"
			switch kind {
			case "file":
				invalid = filepath.Join(home, "file")
				if err := os.WriteFile(invalid, []byte("unchanged"), 0600); err != nil {
					t.Fatal(err)
				}
			case "control":
				invalid = filepath.Join(home, "bad\tpath")
			}
			var output bytes.Buffer
			want := filepath.Join(home, "goinfre", "lima-home")
			got, err := resolveHome(home, strings.NewReader(invalid+"\n\n"), &output)
			if err != nil || got != want {
				t.Fatalf("resolveHome() = %q, %v; want %q, nil", got, err, want)
			}
			if strings.Count(output.String(), storagePrompt) != 2 ||
				strings.Count(output.String(), "Invalid storage directory:") != 1 {
				t.Fatalf("expected one rejection and two prompts, got %q", output.String())
			}
			assertSavedStorageHome(t, home, want)
			if kind == "control" {
				assertStorageAbsent(t, invalid)
			}
			if kind == "file" {
				data, err := os.ReadFile(invalid)
				if err != nil || string(data) != "unchanged" {
					t.Fatalf("invalid file was modified: %q, %v", data, err)
				}
			}
		})
	}
}

func TestResolveHomeEOFCancels(t *testing.T) {
	for _, kind := range []string{"empty", "partial", "after-invalid"} {
		t.Run(kind, func(t *testing.T) {
			home := t.TempDir()
			partial := filepath.Join(home, "custom")
			input := ""
			switch kind {
			case "partial":
				input = partial
			case "after-invalid":
				input = "relative/path\n"
			}
			var output bytes.Buffer
			got, err := resolveHome(home, strings.NewReader(input), &output)
			if got != "" || !errors.Is(err, io.EOF) {
				t.Fatalf("resolveHome() = %q, %v; want empty result and EOF", got, err)
			}
			assertStorageAbsent(t, filepath.Join(home, "goinfre"))
			assertStorageAbsent(t, partial)
		})
	}
}

func TestResolveHomeInvalidSavedConfig(t *testing.T) {
	disableStoragePrompt(t)
	t.Setenv("LIMA_HOME", "")
	for _, tc := range []struct{ name, data string }{
		{"corrupt", "{"},
		{"missing-home", "{}"},
		{"empty-home", `{"home":""}`},
		{"null", "null"},
		{"wrong-type", `{"home":123}`},
		{"relative", `{"home":"relative/path"}`},
		{"control", `{"home":"/bad\u0000path"}`},
		{"file", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			if tc.name == "file" {
				file := filepath.Join(home, "file")
				if err := os.WriteFile(file, nil, 0600); err != nil {
					t.Fatal(err)
				}
				writeSavedStorageHome(t, home, file)
			} else {
				writeStorageConfig(t, home, tc.data)
			}
			var output bytes.Buffer
			for _, input := range []io.Reader{nil, unexpectedStorageInput{t}} {
				got, err := resolveHome(home, input, &output)
				if got != "" || err == nil || !strings.Contains(err.Error(), storageConfigPath(home)) {
					t.Fatalf("resolveHome() = %q, %v; want config error without fallback", got, err)
				}
			}
			if output.Len() != 0 {
				t.Fatalf("invalid config triggered prompting: %q", output.String())
			}
			if got, err := LimaDir(); err == nil || got != "" {
				t.Fatalf("LimaDir() = %q, %v; want config error without fallback", got, err)
			}
			assertStorageAbsent(t, filepath.Join(home, "goinfre", "lima-home"))
		})
	}
}

func TestLimaDirNoninteractiveDefault(t *testing.T) {
	disableStoragePrompt(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LIMA_HOME", "")
	want := filepath.Join(home, "goinfre", "lima-home")
	if got, err := LimaDir(); err != nil || got != want {
		t.Fatalf("LimaDir() = %q, %v; want %q, nil", got, err, want)
	}
	assertStorageAbsent(t, filepath.Join(home, "goinfre"))
}

func TestLimaDirExplicitEnvironmentPrecedence(t *testing.T) {
	disableStoragePrompt(t)
	for _, scenario := range []string{"saved", "corrupt", "without-home"} {
		t.Run(scenario, func(t *testing.T) {
			home := t.TempDir()
			want := filepath.Join(home, "explicit-not-created")
			t.Setenv("HOME", home)
			t.Setenv("LIMA_HOME", want)
			switch scenario {
			case "saved":
				writeSavedStorageHome(t, home, filepath.Join(home, "saved"))
			case "corrupt":
				writeStorageConfig(t, home, "{")
			case "without-home":
				t.Setenv("HOME", "")
			}
			if got, err := LimaDir(); err != nil || got != want {
				t.Fatalf("LimaDir() = %q, %v; want explicit %q, nil", got, err, want)
			}
			assertStorageAbsent(t, want)
		})
	}
}

func TestSavedStorageMissingDirectoryAllowed(t *testing.T) {
	disableStoragePrompt(t)
	home := t.TempDir()
	want := filepath.Join(home, "missing", "storage")
	writeSavedStorageHome(t, home, want)
	t.Setenv("HOME", home)
	t.Setenv("LIMA_HOME", "")
	var output bytes.Buffer
	got, err := resolveHome(home, unexpectedStorageInput{t}, &output)
	if err != nil || got != want || output.Len() != 0 {
		t.Fatalf("saved lookup = %q, %v, output %q; want %q without prompting", got, err, output.String(), want)
	}
	if got, err := LimaDir(); err != nil || got != want {
		t.Fatalf("LimaDir() = %q, %v; want %q, nil", got, err, want)
	}
	assertStorageAbsent(t, filepath.Join(home, "missing"))
}

func TestLimaDirResolvesSymlinks(t *testing.T) {
	disableStoragePrompt(t)
	for _, source := range []string{"environment", "config"} {
		t.Run(source, func(t *testing.T) {
			home := t.TempDir()
			target := t.TempDir()
			link := filepath.Join(home, "link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			want, err := filepath.EvalSymlinks(target)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			t.Setenv("LIMA_HOME", "")
			if source == "environment" {
				t.Setenv("LIMA_HOME", link)
			} else {
				writeSavedStorageHome(t, home, link)
			}
			if got, err := LimaDir(); err != nil || got != want {
				t.Fatalf("LimaDir() = %q, %v; want resolved %q, nil", got, err, want)
			}
		})
	}
}

func TestResolveHomeUnwritableDirectoryRetries(t *testing.T) {
	home := t.TempDir()
	locked := filepath.Join(home, "locked")
	if err := os.Mkdir(locked, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(locked, 0700); err != nil {
			t.Error(err)
		}
	})
	// Elevated users can bypass directory permissions, so establish that the
	// filesystem actually denies writes before testing the resolver's retry.
	probe, err := os.CreateTemp(locked, "permission-check-")
	if err == nil {
		probe.Close()
		os.Remove(probe.Name())
		t.Skip("current user can write to a directory with mode 0500")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("unexpected permission probe error: %v", err)
	}
	var output bytes.Buffer
	want := filepath.Join(home, "goinfre", "lima-home")
	got, err := resolveHome(home, strings.NewReader(locked+"\n\n"), &output)
	if err != nil || got != want {
		t.Fatalf("resolveHome() = %q, %v; want %q, nil", got, err, want)
	}
	if strings.Count(output.String(), storagePrompt) != 2 || !strings.Contains(output.String(), "Invalid storage directory:") {
		t.Fatalf("expected unwritable path rejection and retry, got %q", output.String())
	}
	assertSavedStorageHome(t, home, want)
}

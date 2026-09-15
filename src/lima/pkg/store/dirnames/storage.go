package dirnames

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
)

var (
	homePromptEnabled atomic.Bool
	homeMu            sync.Mutex
)

// SetHomePromptEnabled lets the CLI opt into first-use setup after parsing flags.
// Library users, background commands, and non-interactive callers do not prompt.
func SetHomePromptEnabled(enabled bool) {
	homePromptEnabled.Store(enabled)
}

type homeSettings struct {
	Home string `json:"home"`
}

func resolveHome(homeDir string, input io.Reader, output io.Writer) (string, error) {
	// Multiple storage lookups in one process must not display competing prompts.
	homeMu.Lock()
	defer homeMu.Unlock()

	defaultDir := filepath.Join(homeDir, "goinfre", "lima-home")
	configPath := filepath.Join(homeDir, "goinfre", "lima-config.json")
	data, err := os.ReadFile(configPath)
	if err == nil {
		var settings homeSettings
		if err := json.Unmarshal(data, &settings); err != nil {
			return "", fmt.Errorf("read Lima storage setting %q: %w; fix the file or set LIMA_HOME", configPath, err)
		}
		dir, err := normalizeHome(settings.Home, homeDir)
		if err != nil {
			return "", fmt.Errorf("invalid Lima storage setting in %q: %w; fix the file or set LIMA_HOME", configPath, err)
		}
		return dir, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read Lima storage setting %q: %w", configPath, err)
	}
	if input == nil {
		// Do not consume piped input or persist an unconfirmed choice in scripts.
		return defaultDir, nil
	}

	reader := bufio.NewReader(input)
	for {
		if _, err := fmt.Fprint(output, "Lima storage directory [~/goinfre/lima-home]: "); err != nil {
			return "", err
		}
		answer, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("Lima storage setup cancelled: %w; set LIMA_HOME for non-interactive use", err)
		}
		answer = strings.TrimSpace(answer)
		if answer == "" {
			answer = defaultDir
		}
		dir, err := normalizeHome(answer, homeDir)
		if err == nil {
			err = prepareHome(dir)
		}
		if err != nil {
			fmt.Fprintf(output, "Invalid storage directory: %v\n", err)
			continue
		}
		if err := saveHome(configPath, dir); err != nil {
			return "", fmt.Errorf("save Lima storage setting %q: %w", configPath, err)
		}
		fmt.Fprintf(output, "Lima storage directory saved: %s\n", dir)
		return dir, nil
	}
}

func normalizeHome(dir, homeDir string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "~" {
		dir = homeDir
	} else if strings.HasPrefix(dir, "~/") {
		dir = filepath.Join(homeDir, dir[2:])
	}
	if !filepath.IsAbs(dir) || strings.IndexFunc(dir, unicode.IsControl) >= 0 {
		return "", errors.New("enter an absolute directory path or a path beginning with ~/")
	}
	dir = filepath.Clean(dir)
	info, err := os.Stat(dir)
	if err == nil && !info.IsDir() {
		return "", fmt.Errorf("%q is not a directory", dir)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return dir, nil
}

func prepareHome(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	probe, err := os.CreateTemp(dir, ".lima-write-test-*")
	if err != nil {
		return fmt.Errorf("directory is not writable: %w", err)
	}
	defer os.Remove(probe.Name())
	return probe.Close()
}

func saveHome(configPath, dir string) error {
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(homeSettings{Home: dir}, "", "  ")
	if err != nil {
		return err
	}
	// Rename a private, complete file so later commands cannot read partial JSON.
	file, err := os.CreateTemp(filepath.Dir(configPath), ".lima-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(append(data, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), configPath)
}

// Package command selects dedicated native workers or explicit external QEMU commands.
package command

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/lima-vm/lima/pkg/embeddedassets"
	"github.com/mattn/go-shellwords"
)

const (
	QEMU    = "--internal-qemu"
	QEMUImg = "--internal-qemu-img"
)

func resolve(env, mode string) (string, []string, error) {
	if value := os.Getenv(env); value != "" {
		words, err := shellwords.Parse(value)
		if err != nil {
			return "", nil, fmt.Errorf("failed to parse %s: %w", env, err)
		}
		if len(words) == 0 || words[0] == "" {
			return "", nil, fmt.Errorf("%s must name an executable", env)
		}
		exe, err := exec.LookPath(words[0])
		if err != nil {
			return "", nil, fmt.Errorf("resolve %s: %w", env, err)
		}
		return exe, words[1:], nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", nil, err
	}
	return exe, []string{mode}, nil
}

func System(arch string) (string, []string, error) {
	if err := embeddedassets.CheckArch(arch); err != nil {
		return "", nil, err
	}
	return resolve("QEMU_SYSTEM_"+strings.ToUpper(arch), QEMU)
}

func Image() (string, []string, error) {
	return resolve("QEMU_IMG", QEMUImg)
}

// New preserves worker/override prefixes without mutating the caller's arguments.
func New(exe string, prefix []string, args ...string) *exec.Cmd {
	argv := append([]string(nil), prefix...)
	return exec.Command(exe, append(argv, args...)...)
}

func ImageCmd(args ...string) (*exec.Cmd, error) {
	exe, prefix, err := Image()
	if err != nil {
		return nil, err
	}
	return New(exe, prefix, args...), nil
}

func IsBundledSystem(prefix []string) bool {
	return len(prefix) > 0 && prefix[0] == QEMU
}

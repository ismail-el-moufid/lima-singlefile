package main

import (
	"fmt"
	"io"
	"regexp"
	"runtime"
	"strings"

	"github.com/lima-vm/lima/pkg/qemu/command"
)

func init() {
	// init runs on the startup thread. Keep main there until native dispatch;
	// locking only in main is too late to guarantee Darwin's pthread_main_np.
	runtime.LockOSThread()
}

var memoryPrealloc = regexp.MustCompile(`(?i)(?:^|[,{[:space:].])"?prealloc"?(?:[[:space:]]*[:=][[:space:]]*"?(?:on|yes|true|1)(?:["},[:space:]]|$)|[[:space:]]*(?:[,}]|$))`)

func validateInternalArgs(args []string) error {
	for _, arg := range args {
		if strings.IndexByte(arg, 0) >= 0 {
			return fmt.Errorf("native QEMU arguments must not contain NUL bytes")
		}
		option := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
		if strings.HasPrefix(arg, "-") && (option == "daemonize" || option == "mem-prealloc") {
			return fmt.Errorf("%s is unavailable in embedded QEMU: workers must stay in the foreground without memory preallocation", arg)
		}
		if memoryPrealloc.MatchString(arg) {
			return fmt.Errorf("memory preallocation is unavailable in embedded QEMU: %s", arg)
		}
	}
	return nil
}

// dispatchInternal runs before Cobra, root checks, storage resolution, and hostagent
// signal registration. Native exit() terminates this dedicated worker, not a VM's
// parent hostagent. Worker stdout belongs exclusively to QEMU (including JSON/QMP).
func dispatchInternal(args []string, stderr io.Writer, run func(string, []string) int) (bool, int) {
	if len(args) == 0 || (args[0] != command.QEMU && args[0] != command.QEMUImg) {
		return false, 0
	}
	if err := validateInternalArgs(args[1:]); err != nil {
		fmt.Fprintln(stderr, err)
		return true, 1
	}
	return true, run(args[0], args[1:])
}

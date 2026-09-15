package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/lima-vm/lima/pkg/store/dirnames"
	"github.com/lima-vm/lima/pkg/version"
	"github.com/mattn/go-isatty"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	DefaultInstanceName = "default"
)

func main() {
	if handled, code := dispatchInternal(os.Args[1:], os.Stderr, runNative); handled {
		os.Exit(code)
	}
	if err := newApp().Execute(); err != nil {
		handleExitCoder(err)
		logrus.Fatal(err)
	}
}

func newApp() *cobra.Command {
	examplesDir := "limactl start --list-templates (embedded in this executable)"

	var rootCmd = &cobra.Command{
		Use:     "limactl",
		Short:   "Lima: Linux virtual machines",
		Version: strings.TrimPrefix(version.Version, "v"),
		Example: fmt.Sprintf(`  Start the default instance:
  $ limactl start

  Open a shell:
  $ lima

  Run a container:
  $ lima nerdctl run -d --name nginx -p 8080:80 nginx:alpine

  Stop the default instance:
  $ limactl stop

  See also example YAMLs: %s`, examplesDir),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	rootCmd.PersistentFlags().Bool("debug", false, "debug mode")
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		debug, _ := cmd.Flags().GetBool("debug")
		if debug {
			logrus.SetLevel(logrus.DebugLevel)
		}
		if runtime.GOOS == "windows" && isatty.IsCygwinTerminal(os.Stdout.Fd()) {
			formatter := new(logrus.TextFormatter)
			// the default setting does not recognize cygwin on windows
			formatter.ForceColors = true
			logrus.StandardLogger().SetFormatter(formatter)
		}
		if os.Geteuid() == 0 {
			return errors.New("must not run as the root")
		}
		// Validate storage settings without prompting before the command runs.
		dirnames.SetHomePromptEnabled(false)
		if cmd.Name() == "start" {
			if listTemplates, _ := cmd.Flags().GetBool("list-templates"); listTemplates {
				return nil
			}
		}
		if _, err := dirnames.LimaDir(); err != nil {
			return err
		}
		// Enable lazy setup only for foreground terminal commands. Hidden
		// commands include the hostagent and shell-completion requests.
		interactive := !cmd.Hidden && isatty.IsTerminal(os.Stdin.Fd()) &&
			isatty.IsTerminal(os.Stdout.Fd()) && isatty.IsTerminal(os.Stderr.Fd())
		if cmd.Flags().Lookup("tty") != nil {
			tty, _ := cmd.Flags().GetBool("tty")
			interactive = interactive && tty
		}
		dirnames.SetHomePromptEnabled(interactive)
		return nil
	}
	rootCmd.AddCommand(
		newStartCommand(),
		newStopCommand(),
		newShellCommand(),
		newCopyCommand(),
		newListCommand(),
		newDeleteCommand(),
		newValidateCommand(),
		newSudoersCommand(),
		newPruneCommand(),
		newHostagentCommand(),
		newInfoCommand(),
		newShowSSHCommand(),
		newDebugCommand(),
		newEditCommand(),
		newFactoryResetCommand(),
		newLicensesCommand(),
	)
	return rootCmd
}

type ExitCoder interface {
	error
	ExitCode() int
}

func handleExitCoder(err error) {
	if err == nil {
		return
	}

	if exitErr, ok := err.(ExitCoder); ok {
		os.Exit(exitErr.ExitCode())
		return
	}
}

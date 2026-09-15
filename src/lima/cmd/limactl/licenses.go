package main

import (
	"fmt"
	"io/fs"

	"github.com/lima-vm/lima/pkg/embeddedassets"
	"github.com/spf13/cobra"
)

func newLicensesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "licenses",
		Short: "Show embedded Lima license and asset notes",
		Args:  cobra.NoArgs,
		// Reading distribution notices never needs storage setup or root checks.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, name := range []string{"LICENSE", "NOTES.md"} {
				data, err := fs.ReadFile(embeddedassets.Notices(), name)
				if err != nil {
					return err
				}
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "=== %s ===\n%s\n", name, data); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

package main

import (
	"os"

	"github.com/lima-vm/lima/pkg/downloader"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newPruneCommand() *cobra.Command {
	pruneCommand := &cobra.Command{
		Use:               "prune",
		Short:             "Prune garbage objects",
		Args:              cobra.NoArgs,
		RunE:              pruneAction,
		ValidArgsFunction: cobra.NoFileCompletions,
	}
	return pruneCommand
}

func pruneAction(cmd *cobra.Command, args []string) error {
	cacheDir, err := downloader.CacheDir()
	if err != nil {
		return err
	}
	logrus.Infof("Pruning %q", cacheDir)
	return os.RemoveAll(cacheDir)
}

package cmd

import (
	"fmt"

	"github.com/gini/dexter/version"
	"github.com/spf13/cobra"
)

var (
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of dexter",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf(`%s
Version    : %s
Git Commit : %s
Build Time : %s`, BANNER, version.VERSION, version.GITHASH, version.DOB)
			fmt.Println()
		},
	}
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

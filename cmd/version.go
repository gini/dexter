package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/andrewsav-datacom/dexter/version"
)

var (
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of dexter",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf(`%s
Version    : %s`, BANNER, version.VERSION)
			fmt.Println()
		},
	}
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

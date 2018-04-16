package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/gini/dexter/version"
)

var (
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of dexter",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf(`%s
Version    : %s
Git Hash   : %s
Birth Date : %s`, BANNER, version.VERSION, version.GITHASH, version.DOB)
			fmt.Println()
		},
	}
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

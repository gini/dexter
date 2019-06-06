package cmd

import (
	"fmt"

	"github.com/davidr-asapp/dexter-kubeauth/version"
	"github.com/spf13/cobra"
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

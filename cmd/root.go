package cmd

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	BANNER = `    .___               __                
  __| _/____ ___  ____/  |_  ___________ 
 / __ |/ __ \\  \/  /\   __\/ __ \_  __ \
/ /_/ \  ___/ >    <  |  | \  ___/|  | \/
\____ |\___  >__/\_ \ |__|  \___  >__|   
     \/    \/      \/           \/       
`
)

var (
	verbose bool
	timeout int

	rootCmd = &cobra.Command{
		Use:   "dexter",
		Short: "A OpenId connect authentication helper for Kubernetes",
		Long: fmt.Sprintf(`%s
dexter is a authentication helper for Kubernetes that does the heavy
lifting for SSO (Single Sign On) for Kubernetes.`, BANNER),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				log.SetLevel(log.DebugLevel)
			}
			return nil
		},
	}
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", 2, "Timeout for HTTP requests to OIDC providers")
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

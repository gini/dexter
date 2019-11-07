package cmd

import (
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleOIDC struct {
	DexterOIDC
}

var (
	googleProvider = &GoogleOIDC{
		DexterOIDC{
			Oauth2Config: &oauth2.Config{},
			httpClient:   &http.Client{Timeout: 2 * time.Second},
			quitChan:     make(chan struct{}),
			signalChan:   make(chan os.Signal, 1),
		},
	}

	googleCmd = &cobra.Command{
		Use:   "google",
		Short: "Authenticate with OIDC provider",
		Long: `Use your Google login to get a JWT (JSON Web Token) and update your
local k8s config accordingly. A refresh token is added and automatically refreshed 
by kubectl. Existing token configurations are overwritten.
For details go to: https://blog.gini.net/

dexters authentication flow
===========================

1. Open a browser window/tab and redirect you to Google (https://accounts.google.com)
2. You login with your Google credentials
3. You will be redirected to dexters builtin webserver and can now close the browser tab
4. dexter extracts the token from the callback and patches your ~/.kube/config

➜ Unless you have a good reason to do so please use the built-in google credentials (if they were added at build time)!
`,
		Run: GoogleCommand,
	}
)

func init() {
	// add the auth command
	AuthCmd.AddCommand(googleCmd)
}

func GoogleCommand(cmd *cobra.Command, args []string) {
	googleProvider.initialize()

	googleProvider.Oauth2Config.Endpoint = google.Endpoint
	googleProvider.Oauth2Config.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}

	if err := AuthenticateToProvider(googleProvider); err != nil {
		log.Errorf("Authentication failed: %s", err)
	}
}

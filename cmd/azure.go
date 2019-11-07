package cmd

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

type AzureOIDC struct {
	DexterOIDC        // embed the base provider
	tenant     string // azure tenant
}

func (a *AzureOIDC) Autopilot() error {
	authInfo, err := ExtractAuthInfo(a.kubeConfig)

	if err != nil {
		return fmt.Errorf("failed to extract oidc configuration from the kube config: %s", err)
	}

	// fallback ti tenant common
	a.tenant = "common"

	// call parent method to initialize client credentials
	a.DexterOIDC.AuthInfoToOauth2(authInfo)

	// populate oauth2 config
	a.Oauth2Config.RedirectURL = a.callback
	a.Oauth2Config.ClientID = a.clientID
	a.Oauth2Config.ClientSecret = a.clientSecret

	// extract the issuer url
	idp := authInfo.AuthProvider.Config["idp-issuer-url"]

	// set endpoint based on a match on the issuer URL
	if strings.Contains(idp, "microsoft") {
		//find a uuid, this is the tenant
		re, err := regexp.Compile(`[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}`)

		if err != nil {
			// failed to extract the azure tenant, use default "common
			return err
		}

		res := re.FindStringSubmatch(idp)
		if len(res) == 1 {
			a.tenant = res[0] // found tenant
			return nil
		}
	}

	return fmt.Errorf("no Microsoft auth provider configuration found")
}

var (
	// initialize dexter OIDC config
	azureProvider = &AzureOIDC{
		DexterOIDC{
			Oauth2Config: &oauth2.Config{},
			httpClient:   &http.Client{Timeout: 2 * time.Second},
			quitChan:     make(chan struct{}),
			signalChan:   make(chan os.Signal, 1),
		},
		"",
	}

	azureCmd = &cobra.Command{
		Use:   "azure",
		Short: "Authenticate with the Microsoft Azure Identity Provider",
		Long: `Use your Microsoft login to get a JWT (JSON Web Token) and update your
local k8s config accordingly. A refresh token is added and automatically refreshed 
by kubectl. Existing token configurations are overwritten.

For details go to: https://blog.gini.net/

dexters authentication flow
===========================

1. Open a browser window/tab and redirect you to Microsoft (https://login.microsoftonline.com/)
2. You login with your Microsoft credentials
3. You will be redirected to dexters builtin webserver and can now close the browser tab
4. dexter extracts the token from the callback and patches your ~/.kube/config

➜ Unless you have a good reason to do so please use the built-in Microsoft credentials (if they were added at build time)!
`,
		RunE:         AzureCommand,
		SilenceUsage: true,
	}
)

func init() {
	// add the azure auth subcommand
	AuthCmd.AddCommand(azureCmd)

	// setup commandline flags
	azureCmd.PersistentFlags().StringVarP(&azureProvider.tenant, "tenant", "t", "common", "Your azure tenant")
}

func AzureCommand(cmd *cobra.Command, args []string) error {
	azureProvider.initialize()

	azureProvider.Oauth2Config.Endpoint = microsoft.AzureADEndpoint(azureProvider.tenant)
	azureProvider.Oauth2Config.Scopes = []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "email"}

	if err := AuthenticateToProvider(azureProvider); err != nil {
		return fmt.Errorf("authentication failed: %s", err)
	}

	return nil
}

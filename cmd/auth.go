package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/ghodss/yaml"
	"github.com/gini/dexter/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	"golang.org/x/oauth2/okta"
	"gopkg.in/square/go-jose.v2/jwt"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientCmdApi "k8s.io/client-go/tools/clientcmd/api"
	clientCmdLatest "k8s.io/client-go/tools/clientcmd/api/latest"
)

// dexterOIDC: struct to store the required data and provide methods to
// authenticate with Okta OpenID implementation
type dexterOIDC struct {
	endpoint     string         // azure or google or okta
	azureTenant  string         // azure tenant
	clientID     string         // clientID commandline flag
	clientSecret string         // clientSecret commandline flag
	callback     string         // callback URL commandline flag
	state        string         // CSRF protection
	kubeConfig   string         // location of the kube config file
	dryRun       bool           // don't update the kubectl config
	Oauth2Config *oauth2.Config // oauth2 configuration
	k8sMutex     sync.RWMutex   // mutex to prevent simultaneous write to kubectl config
	httpClient   *http.Client   // http client
	httpServer   http.Server    // http server
	quitChan     chan struct{}  // signal for a clean shutdown
	signalChan   chan os.Signal // react on signals from the outside world
}

// initialize the struct, parse commandline flags and install a signal handler
func (d *dexterOIDC) initialize() error {
	// install signal handler
	signal.Notify(
		oidcData.signalChan,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	// get active user (to get the homedirectory)
	usr, err := user.Current()

	if err != nil {
		return errors.New(fmt.Sprintf("failed to determine current user: %s", err))
	}

	// construct the path to the users .kube/config file as a default
	kubeConfigDefaultPath := filepath.Join(usr.HomeDir, ".kube", "config")

	// setup commandline flags
	// NOTE: these OKTA vars depend on the Makefile embedding rules
	AuthCmd.PersistentFlags().StringVarP(&d.endpoint, "endpoint", "e", "okta", "OIDC-providers: google or azure or okta")
	AuthCmd.PersistentFlags().StringVarP(&d.azureTenant, "tenant", "t", "common", "Your azure tenant")
	AuthCmd.PersistentFlags().StringVarP(&d.clientID, "client-id", "i", "OKTA_OIDC_CLIENT_ID", "Google  or Okta clientID")
	AuthCmd.PersistentFlags().StringVarP(&d.clientSecret, "client-secret", "s", "OKTA_OIDC_CLIENT_SECRET", "Google or Okta clientSecret")
	AuthCmd.PersistentFlags().StringVarP(&d.callback, "callback", "c", "OKTA_OIDC_CALLBACK", "Callback URL. The listen address is derived from that.")
	AuthCmd.PersistentFlags().StringVarP(&d.kubeConfig, "kube-config", "k", kubeConfigDefaultPath, "Overwrite the default location of kube config (~/.kube/config)")
	AuthCmd.PersistentFlags().BoolVarP(&d.dryRun, "dry-run", "d", false, "Toggle config overwrite")

	// create random string as CSRF protection for the oauth2 flow
	d.state = utils.RandomString()

	return nil
}

// setup and populate the OAuth2 config
func (d *dexterOIDC) createOauth2Config() error {
	// no commandline client credentials supplied
	if d.clientID == "REDACTED" && d.clientSecret == "REDACTED" {
		// no builtin defaults - let's try auto-configuration
		if defaultClientID == "" && defaultClientSecret == "" {
			log.Info("Autopilot mode - no credentials set")
			if err := d.autoConfigureOauth2Config(); err != nil {
				return errors.New(fmt.Sprintf("failed to extract oidc configuration from the kube config: %s", err))
			}
		} else if defaultClientID != "" && defaultClientSecret != "" {
			// use build-time defaults if no clientId & clientSecret was provided
			log.Info("Using builtin credentials - no credentials set")
			d.clientID = defaultClientID
			d.clientSecret = defaultClientSecret
		}
	}

	// setup oidc client context
	oidc.ClientContext(context.Background(), d.httpClient)

	// populate oauth2 config
	d.Oauth2Config.ClientID = oidcData.clientID
	d.Oauth2Config.ClientSecret = oidcData.clientSecret
	d.Oauth2Config.RedirectURL = oidcData.callback

	switch oidcData.endpoint {
	case "azure":
		d.Oauth2Config.Endpoint = microsoft.AzureADEndpoint(oidcData.azureTenant)
		d.Oauth2Config.Scopes = []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "email"}
	case "google":
		d.Oauth2Config.Endpoint = google.Endpoint
		d.Oauth2Config.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	case "okta":
		d.Oauth2Config.Endpoint = okta.Endpoint
		d.Oauth2Config.Scopes = []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "profile", "email", "email_verified", "groups"}
	default:
		return errors.New(fmt.Sprintf("unsupported endpoint: %s", oidcData.endpoint))
	}

	return nil
}

// populate the Oauth2Config object from the kube config. Return an error when the operation failed
func (d *dexterOIDC) autoConfigureOauth2Config() error {
	// initialize the clientConfig and error variables
	var clientCfg *clientCmdApi.Config
	var err error

	// try to load the credentials from the kubeconfig specified on the commandline
	if d.kubeConfig != "" {
		clientCfg, err = clientcmd.LoadFromFile(d.kubeConfig)

		if err != nil {
			return errors.New(fmt.Sprintf("failed to load kubeconfig from %s: %s", d.kubeConfig, err))
		}
	} else {
		// try to load credentials from CurrentContext
		clientCfg, err = clientcmd.NewDefaultClientConfigLoadingRules().Load()

		if err != nil {
			return errors.New(fmt.Sprintf("failed to load kubeconfig from the default locations: %s", err))
		}
	}

	// loop through all the contexts until we find the current context
	for contextName, context := range clientCfg.Contexts {
		// find the context definition that matches the current active context
		if contextName == clientCfg.CurrentContext {
			// loop through the global authentication definitions
			for authName, authInfo := range clientCfg.AuthInfos {
				// find the authentication definition that is in use in the current context
				if authName == context.AuthInfo {
					// ensure it is oidc based
					if authInfo.AuthProvider != nil && authInfo.AuthProvider.Name == "oidc" {
						// verify that relevant keys exist
						for _, key := range []string{"client-id", "client-secret", "idp-issuer-url"} {
							if _, ok := authInfo.AuthProvider.Config[key]; !ok {
								return errors.New(fmt.Sprintf("%s is missing in kubeconfig: %s", key, err))
							}
						}

						// set client credentials and idp url based on the kubeconfig definition
						d.clientSecret = authInfo.AuthProvider.Config["client-secret"]
						d.clientID = authInfo.AuthProvider.Config["client-id"]
						idp := authInfo.AuthProvider.Config["idp-issuer-url"]

						// set endpoint based on a match on the issuer URL
						if strings.Contains(idp, "google") {
							oidcData.endpoint = "google"

						} else if strings.Contains(idp, "microsoft") {
							oidcData.endpoint = "azure"

						} else if strings.Contains(idp, "okta") {
							oidcData.endpoint = "okta"

							re, err := regexp.Compile(`[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}`) //find uuid, this is tenant

							if err != nil {
								// failed to extract the azure tenant, use default "common
								oidcData.azureTenant = "common"
								return nil

							}

							res := re.FindStringSubmatch(idp)
							if len(res) == 1 {
								oidcData.azureTenant = res[0] // found tenant
							} else {
								// failed to find tenant, use common
								oidcData.azureTenant = "common"
							}
						}

						return nil
					}
				}
			}
		}
	}

	return errors.New("failed to auto-configure OIDC from kubeconfig")
}

func (d *dexterOIDC) authUrl() string {
	return d.Oauth2Config.AuthCodeURL(d.state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))
}

// start HTTP server to receive callbacks. This has to be run in a go routine
func (d *dexterOIDC) startHttpServer() {
	// set HTTP server listen address from callback URL
	parsedURL, err := url.Parse(d.callback)

	if err != nil {
		log.Errorf("Failed to parse callback URL: %s", err)
		d.quitChan <- struct{}{}
	}

	d.httpServer.Addr = parsedURL.Host
	http.HandleFunc("/callback", d.callbackHandler)
	d.httpServer.ListenAndServe()
}

// accept callbacks from your browser
func (d *dexterOIDC) callbackHandler(w http.ResponseWriter, r *http.Request) {

	// Get code and state from the passed form value
	code := r.FormValue("code")
	callbackState := r.FormValue("state")

	// verify code AND state are defined
	if code == "" || callbackState == "" {
		log.Errorf("no code or state in request: %q", r.Form)
		http.Error(w, "no code or state found in your request", http.StatusBadRequest)
		return
	}

	// compare callback state and initial state
	if callbackState != oidcData.state {
		log.Error("state mismatch! Someone could be tampering with your connection!")
		http.Error(w, "state mismatch! Someone could be tampering with your connection!", http.StatusBadRequest)
		return
	}

	log.Info("authCode and state verification passed. Fetching JWT")

	// create context and exchange authCode for token
	ctx := oidc.ClientContext(r.Context(), d.httpClient)

	token, err := oidcData.Oauth2Config.Exchange(ctx, code)

	if err != nil {
		log.Errorf("Failed to exchange auth code: %s", err)
		http.Error(w, "Failed to exchange auth code!", http.StatusInternalServerError)
		return
	}

	log.Info("exchanged authCode for JWT token. Refresh token was supplied")

	if err := d.writeK8sConfig(token); err != nil {
		log.Errorf("Failed to write k8s config: %s", err)
		http.Error(w, fmt.Sprintf("Failed to write k8s config: %s", err), http.StatusInternalServerError)
		return
	}

	// We're done here
	oidcData.quitChan <- struct{}{}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<html><body>Authentication completed. It's safe to close this window now ;-)</body></html>"))

	return
}

type CustomClaim struct {
	Email string `json:"email"`
}

// write the k8s config
func (d *dexterOIDC) writeK8sConfig(token *oauth2.Token) error {
	// acquire lock
	d.k8sMutex.Lock()
	defer d.k8sMutex.Unlock()

	idToken := token.Extra("id_token").(string)

	parsed, err := jwt.ParseSigned(idToken)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to parse token: %s", err))
	}

	customClaim := &CustomClaim{}
	claims := &jwt.Claims{}

	err = parsed.UnsafeClaimsWithoutVerification(claims, customClaim)

	if err != nil {
		return errors.New(fmt.Sprintf("failed to get user details from token: %s", err))
	}

	email := customClaim.Email

	// construct the authinfo struct
	authInfo := &clientCmdApi.AuthInfo{
		AuthProvider: &clientCmdApi.AuthProviderConfig{
			Name: "oidc",
			Config: map[string]string{
				"client-id":      d.clientID,
				"client-secret":  d.clientSecret,
				"id-token":       idToken,
				"idp-issuer-url": claims.Issuer,
				"refresh-token":  token.RefreshToken,
			},
		},
	}

	// contruct the config snippet
	config := &clientCmdApi.Config{
		AuthInfos: map[string]*clientCmdApi.AuthInfo{email: authInfo},
	}

	log.Infof("\n\n====> config: \n====> %v\n\n", config)
	// write the rendered config snipped when dry-run is enabled
	if oidcData.dryRun {
		// create a JSON representation
		json, err := k8sRuntime.Encode(clientCmdLatest.Codec, config)

		if err != nil {
			return errors.New(fmt.Sprintf("failed to runtime encode config: %s", err))
		}

		// convert JSON to YAML
		output, err := yaml.JSONToYAML(json)

		if err != nil {
			return errors.New(fmt.Sprintf("failed to convert JSON to YAML: %s", err))
		}

		// show the result
		log.Infof("Here's the config snippet that would be merged with your config: \n%v", string(output))

		return nil
	}

	// write the config
	tempKubeConfig, err := ioutil.TempFile("", "")
	defer os.Remove(tempKubeConfig.Name())

	if err != nil {
		return errors.New(fmt.Sprintf("failed to create tempfile: %s", err))
	}

	// write snipped to temporary file
	clientcmd.WriteToFile(*config, tempKubeConfig.Name())

	// setup the order for the file load
	loadingRules := clientcmd.ClientConfigLoadingRules{
		Precedence: []string{tempKubeConfig.Name(), d.kubeConfig},
	}

	// merge the configs
	mergedConfig, err := loadingRules.Load()

	if err != nil {
		return errors.New(fmt.Sprintf("failed to merge configurations: %s", err))
	}

	// write the merged data to the k8s config
	err = clientcmd.WriteToFile(*mergedConfig, d.kubeConfig)

	if err != nil {
		return errors.New(fmt.Sprintf("failed to write merged configuration: %s", err))
	}

	return nil
}

var (
	// default injected at build time. This is optional
	defaultClientID     string
	defaultClientSecret string

	// initialize dexter OIDC config
	oidcData = dexterOIDC{
		Oauth2Config: &oauth2.Config{},
		httpClient:   &http.Client{Timeout: 2 * time.Second},
		quitChan:     make(chan struct{}),
		signalChan:   make(chan os.Signal, 1),
	}

	// Cobra command
	AuthCmd = &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with OIDC provider",
		Long: `Use your Google or Okta login to get a JWT (JSON Web Token) and update your
local k8s config accordingly. A refresh token is added and automatically refreshed 
by kubectl. Existing token configurations are overwritten.
For details go to: https://blog.gini.net/

dexters authentication flow
===========================

1. Open a browser window/tab and redirect you to Google (https://accounts.google.com) or Okta (your Okta endpoint)
2. You login with your Google or Okta credentials
3. You will be redirected to dexters builtin webserver and can now close the browser tab
4. dexter extracts the token from the callback and patches your ~/.kube/config

➜ For google: unless you have a good reason to do so please use the built-in google credentials (if they were added at build time)!
`,
		Run: authCommand,
	}
)

// initialize the command
func init() {
	// add the auth command
	rootCmd.AddCommand(AuthCmd)

	// parse commandline flags
	if err := oidcData.initialize(); err != nil {
		log.Errorf("Failed to initialize OIDC provider: %s", err)
		os.Exit(1)
	}
}

// the command to run
func authCommand(cmd *cobra.Command, args []string) {
	if oidcData.clientID == "" || oidcData.clientSecret == "" {
		log.Error("clientID and clientSecret cannot be empty!")
		return
	}

	// setup oauth2 object
	if err := oidcData.createOauth2Config(); err != nil {
		log.Errorf("oauth2 configuration failed: %s", err)
		return
	}

	log.Info("Starting auth browser session. Please check your browser instances...")

	if err := utils.OpenURL(oidcData.authUrl()); err != nil {
		log.Errorf("Failed to open browser session: %s", err)
		return
	}

	log.Infof("Spawning http server to receive callbacks (%s)", oidcData.callback)

	// spawn HTTP server
	go oidcData.startHttpServer()

	for {
		select {
		// flow was completed or error occured
		case <-oidcData.quitChan:
			log.Debugf("Shutdown signal received. We're done here")

			ctx, _ := context.WithTimeout(context.Background(), 1*time.Second)

			oidcData.httpServer.Shutdown(ctx)
			log.Infof("Shutdown completed")
			os.Exit(0)
		// OS signal was received
		case sig := <-oidcData.signalChan:
			log.Infof("Signal %d (%s) received. Initiating shutdown", sig, sig)
			close(oidcData.quitChan)
		default:
		}
	}
}

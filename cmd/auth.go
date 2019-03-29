package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/ghodss/yaml"
	"github.com/gini/dexter/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	"gopkg.in/square/go-jose.v2/jwt"
	"io/ioutil"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientCmdApi "k8s.io/client-go/tools/clientcmd/api"
	clientCmdLatest "k8s.io/client-go/tools/clientcmd/api/latest"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// dexterOIDC: struct to store the required data and provide methods to
// authenticate with Googles OpenID implementation
type dexterOIDC struct {
	endpoint     string         // azure or google
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
	AuthCmd.PersistentFlags().StringVarP(&d.endpoint, "endpoint", "e", "google", "OIDC-providers: google or azure")
	AuthCmd.PersistentFlags().StringVarP(&d.azureTenant, "tenant", "t", "common", "Your azure tenant")
	AuthCmd.PersistentFlags().StringVarP(&d.clientID, "client-id", "i", "REDACTED", "Google clientID")
	AuthCmd.PersistentFlags().StringVarP(&d.clientSecret, "client-secret", "s", "REDACTED", "Google clientSecret")
	AuthCmd.PersistentFlags().StringVarP(&d.callback, "callback", "c", "http://127.0.0.1:64464/callback", "Callback URL. The listen address is dreived from that.")
	AuthCmd.PersistentFlags().StringVarP(&d.kubeConfig, "kube-config", "k", kubeConfigDefaultPath, "Overwrite the default location of kube config (~/.kube/config)")
	AuthCmd.PersistentFlags().BoolVarP(&d.dryRun, "dry-run", "d", false, "Toggle config overwrite")

	// create random string as CSRF protection for the oauth2 flow
	d.state = utils.RandomString()

	return nil
}

// setup and populate the OAuth2 config
func (d *dexterOIDC) createOauth2Config() error {

	// try to load credentials from CurrentContext
	clientCfg, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()

	if err == nil {

		for i, context := range clientCfg.Contexts {

			if i == clientCfg.CurrentContext {
				for a, authInfo := range clientCfg.AuthInfos {
					if a == context.AuthInfo {
						if authInfo.AuthProvider != nil && authInfo.AuthProvider.Name == "oidc" {

							d.clientSecret = authInfo.AuthProvider.Config["client-secret"]
							d.clientID = authInfo.AuthProvider.Config["client-id"]

							idp := authInfo.AuthProvider.Config["idp-issuer-url"]

							if strings.Contains(idp, "google") {
								oidcData.endpoint = "google"

							} else if strings.Contains(idp, "microsoft") {
								oidcData.endpoint = "azure"
							}

						}

					}

				}

				continue
			}

		}
	}

	// use build-time defaults if no clientId & clientSecret was provided
	if d.clientID == "REDACTED" {
		d.clientID = defaultClientID
	}

	if d.clientSecret == "REDACTED" {
		d.clientSecret = defaultClientSecret
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
	default:
		return errors.New(fmt.Sprintf("unsupported endpoint: %s", oidcData.endpoint))
	}
	return nil
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
	log.Info("callback received")

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
	log.Infof("writing credentials to %s", d.kubeConfig)

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

	log.Info("Starting Google auth browser session. Please check your browser instances...")

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

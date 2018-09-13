package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/ghodss/yaml"
	"github.com/andrewsav-datacom/dexter/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
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
	"sync"
	"syscall"
	"time"
)

// dexterOIDC: struct to store the required data and provide methods to
// authenticate with Googles OpenID implementation
type dexterOIDC struct {
	clientID     string         // clientID commandline flag
	clientSecret string         // clientSecret commandline flag
	callback     string         // callback URL commandline flag
	state        string         // CSRF protection
	dryRun       bool           // don't update the kubectl config
	emailFile    string         // write user's email to this file for use with other tooling
	Oauth2Config *oauth2.Config // oauth2 configuration
	k8sMutex     sync.RWMutex   // mutex to prevent simultaneous write to kubectl config
	httpClient   *http.Client   // http client
	httpServer   http.Server    // http server
	quitChan     chan struct{}  // signal for a clean shutdown
	signalChan   chan os.Signal // react on signals from the outside world
}

type DiscoverySpec struct {
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	ScopesSupported        []string `json:"scopes_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	UserinfoEndpoint       string   `json:"userinfo_endpoint"`
}

var (
	issuer string = "https://accounts.google.com"
)

// initialize the struct, parse commandline flags and install a signal handler
func (d *dexterOIDC) initialize() error {
	// install signal handler
	signal.Notify(
		oidcData.signalChan,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	// setup commandline flags
	AuthCmd.PersistentFlags().StringVarP(&d.clientID, "client-id", "i", "REDACTED", "Google clientID")
	AuthCmd.PersistentFlags().StringVarP(&d.clientSecret, "client-secret", "s", "REDACTED", "Google clientSecret")
	AuthCmd.PersistentFlags().StringVarP(&d.callback, "callback", "c", "http://127.0.0.1:64464/callback", "Callback URL. The listen address is dreived from that.")
	AuthCmd.PersistentFlags().BoolVarP(&d.dryRun, "dry-run", "d", false, "Toggle config overwrite")
	AuthCmd.PersistentFlags().StringVarP(&d.emailFile, "write-email", "f", "", "Write user email to the specified file for use with other tooling")

	// create random string as CSRF protection for the oauth2 flow
	d.state = utils.RandomString()

	return nil
}

// setup and populate the OAuth2 config
func (d *dexterOIDC) createOauth2Config() error {
	// use build-time defaults if no clientId & clientSecret was provided
	if d.clientID == "REDACTED" {
		if defaultClientID == "" {
			return errors.New(fmt.Sprintf("Client ID is not specified and there was no built-in google credentials added at build time"))
		} else {
			d.clientID = defaultClientID
		}
	}

	if d.clientSecret == "REDACTED" {
		if defaultClientSecret == "" {
			return errors.New(fmt.Sprintf("Client Secret is not specified and there was no built-in google credentials added at build time"))
		} else {
			d.clientSecret = defaultClientSecret
		}
	}

	// setup oidc client context
	ctx := oidc.ClientContext(context.Background(), d.httpClient)

	// initialize oidc provider
	provider, err := oidc.NewProvider(ctx, issuer)

	if err != nil {
		return errors.New(fmt.Sprintf("failed to create new dexterOIDC provider: %s", err))
	}

	// populate oauth2 config
	d.Oauth2Config.ClientID = oidcData.clientID
	d.Oauth2Config.ClientSecret = oidcData.clientSecret
	d.Oauth2Config.RedirectURL = oidcData.callback
	d.Oauth2Config.Endpoint = provider.Endpoint()
	d.Oauth2Config.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}

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
	log.Info("writing credentials to ~/.kube/config")

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

// fetch the users email address with given token
func (d *dexterOIDC) getEmailAddress(accessToken string) (string, error) {
	ds, err := GetDiscoverySpec(issuer)
	if err != nil {
		log.Fatalf("Can not get Discovery Spec: %v", err)
		return "", err		
	}

	uri, _ := url.Parse(ds.UserinfoEndpoint)

	q := uri.Query()
	q.Set("alt", "json")
	q.Set("access_token", accessToken)

	uri.RawQuery = q.Encode()

	resp, err := d.httpClient.Get(uri.String())
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	type UserInfo struct {
		Email string `json:"email"`
	}

	ui := &UserInfo{}
	err = json.NewDecoder(resp.Body).Decode(ui)

	if err != nil {
		return "", err
	}

	return ui.Email, nil
}

// write the k8s config
func (d *dexterOIDC) writeK8sConfig(token *oauth2.Token) error {
	// acquire lock
	d.k8sMutex.Lock()
	defer d.k8sMutex.Unlock()

	// construct the authinfo struct
	authInfo := &clientCmdApi.AuthInfo{
		AuthProvider: &clientCmdApi.AuthProviderConfig{
			Name: "oidc",
			Config: map[string]string{
				"client-id":      d.clientID,
				"client-secret":  d.clientSecret,
				"id-token":       token.Extra("id_token").(string),
				"idp-issuer-url": issuer,
				"refresh-token":  token.RefreshToken,
			},
		},
	}

	// fetch the email address
	email, err := d.getEmailAddress(token.AccessToken)

	if err != nil {
		return errors.New(fmt.Sprintf("failed to get user details with access token: %s", err))
	}

	if oidcData.emailFile != "" {
		log.Info(fmt.Sprintf("writing email to %s", oidcData.emailFile))
		err := ioutil.WriteFile(oidcData.emailFile, []byte(email+"\n"), 0644)
		if err != nil {
			return errors.New(fmt.Sprintf("Error writing email to file: %s", err))
		}
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

	// get active user (to get the homedirectory)
	usr, err := user.Current()

	if err != nil {
		return errors.New(fmt.Sprintf("failed to determine current user: %s", err))
	}

	// construct the path to ~/.kube/config
	kubeConfigPath := filepath.Join(usr.HomeDir, ".kube", "config")

	// setup the order for the file load
	loadingRules := clientcmd.ClientConfigLoadingRules{
		Precedence: []string{tempKubeConfig.Name(), kubeConfigPath},
	}

	// merge the configs
	mergedConfig, err := loadingRules.Load()

	if err != nil {
		return errors.New(fmt.Sprintf("failed to merge configurations: %s", err))
	}

	// write the merged data to the k8s config
	err = clientcmd.WriteToFile(*mergedConfig, kubeConfigPath)

	if err != nil {
		return errors.New(fmt.Sprintf("failed to write merged configuration: %s", err))
	}

	return nil
}

var (
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

1. Open a browser window/tab and redirect you to Google (`+ issuer +`)
2. You login with your Google credentials
3. You will be redirected to dexters builtin webserver and can now close the browser tab
4. dexter extracts the token from the callback and patches your ~/.kube/config

Unless you have a good reason to do so please use the built-in google credentials (if they were added at build time)!
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

func GetDiscoverySpec(issuer string) (DiscoverySpec, error) {
	ds := &DiscoverySpec{}
	resp, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		return *ds, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(ds)
	if err != nil {
		return *ds, err
	}
	return *ds, nil
}

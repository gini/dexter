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
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/ghodss/yaml"
	"github.com/gini/dexter/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientCmdApi "k8s.io/client-go/tools/clientcmd/api"
	clientCmdLatest "k8s.io/client-go/tools/clientcmd/api/latest"
	"k8s.io/client-go/util/homedir"
)

var (
	// default injected at build time. This is optional
	buildTimeClientID     string
	buildTimeClientSecret string
	buildTimeProvider     string

	// commandline flags
	clientID     string
	clientSecret string
	callback     string
	kubeConfig   string
	kubeUsername string
	dryRun       bool

	// Cobra command
	AuthCmd = &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with OIDC provider",
		Long: `Use a provider sub-command to authenticate against your identity provider of choice.
For details go to: https://blog.gini.net/
`,
		RunE: DefaultCommand,
	}
)

// support build time providers. If the variable buildTimeProvider is set run the provider.
// FR: https://github.com/gini/dexter/issues/29
func DefaultCommand(cmd *cobra.Command, args []string) error {
	var realCommand func(cmd *cobra.Command, args []string) error

	// simple approach to select the provider
	switch buildTimeProvider {
	case "google":
		realCommand = GoogleCommand
	case "azure":
		realCommand = AzureCommand
	default:
		// no valid provider found: default to usage
		return cmd.Usage()
	}

	log.Infof("Build time provider set to '%s'. Use flag --help for more options.", buildTimeProvider)
	return realCommand(cmd, args)
}

// helper type to render the k8s config
type CustomClaim struct {
	Email string `json:"email"`
}

// interface that all OIDC providers need to implement
type OIDCProvider interface {
	ConfigureOAuth2Manully() error
	Autopilot() error
	PreflightCheck() error
	GenerateAuthUrl() string
	StartHTTPServer() error
}

// DexterOIDC: struct to store the required data and provide methods to
// authenticate with OpenID providers
type DexterOIDC struct {
	clientID     string         // clientID commandline flag
	clientSecret string         // clientSecret commandline flag
	callback     string         // callback URL commandline flag
	state        string         // CSRF protection
	kubeConfig   string         // location of the kube config file
	kubeUsername string         // name identifier to store the user data
	dryRun       bool           // don't update the kubectl config
	Oauth2Config *oauth2.Config // oauth2 configuration
	k8sMutex     sync.RWMutex   // mutex to prevent simultaneous write to kubectl config
	httpClient   *http.Client   // http client
	httpServer   http.Server    // http server
	quitChan     chan struct{}  // signal for a clean shutdown
	signalChan   chan os.Signal // react on signals from the outside world
}

// ensure that the required parameters are defined and that the values make sense
func (d DexterOIDC) PreflightCheck() error {
	if d.clientID == "" || d.clientSecret == "" {
		return errors.New("clientID and clientSecret cannot be empty")
	}

	return nil
}

// create Oauth2 configuration
func (d *DexterOIDC) AuthInfoToOauth2(authInfo *clientCmdApi.AuthInfo) {
	d.clientSecret = authInfo.AuthProvider.Config["client-secret"]
	d.clientID = authInfo.AuthProvider.Config["client-id"]
}

// attempt to set client credentials
func (d *DexterOIDC) ConfigureOAuth2Manully() error {
	d.Oauth2Config.RedirectURL = d.callback

	// no commandline client credentials supplied
	if d.clientID == "REDACTED" && d.clientSecret == "REDACTED" {
		// no builtin defaults - let's try auto-configuration
		if buildTimeClientID == "" && buildTimeClientSecret == "" {
			return errors.New("cannot set client credentials: empty commandline and builtin defaults")
		} else {
			log.Info("Using builtin credentials - no credentials set")
			d.clientID = buildTimeClientID
			d.clientSecret = buildTimeClientSecret
		}
	}

	// populate oauth2 config
	d.Oauth2Config.ClientID = d.clientID
	d.Oauth2Config.ClientSecret = d.clientSecret

	return nil
}

func (d *DexterOIDC) Autopilot() error {
	log.Info("Autopilot mode - no credentials set")
	if authInfo, err := ExtractAuthInfo(d.kubeConfig); err != nil {
		return errors.New(fmt.Sprintf("failed to extract oidc configuration from the kube config: %s", err))
	} else {
		d.clientSecret = authInfo.AuthProvider.Config["client-secret"]
		d.clientID = authInfo.AuthProvider.Config["client-id"]

		// populate oauth2 config
		d.Oauth2Config.RedirectURL = d.callback
		d.Oauth2Config.ClientID = d.clientID
		d.Oauth2Config.ClientSecret = d.clientSecret
	}

	return nil
}

func (d DexterOIDC) GenerateAuthUrl() string {
	return d.Oauth2Config.AuthCodeURL(d.state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))
}

// start HTTP server to receive callbacks. This has to be run in a go routine
func (d DexterOIDC) StartHTTPServer() error {
	// set HTTP server listen address from callback URL
	parsedURL, err := url.Parse(d.callback)

	if err != nil {
		log.Errorf("Failed to parse callback URL: %s", err)
		d.quitChan <- struct{}{}
	}

	d.httpServer.Addr = parsedURL.Host

	http.HandleFunc("/callback", d.callbackHandler)

	go func(d DexterOIDC) {
		if err := d.httpServer.ListenAndServe(); err != nil {
			log.Errorf("Failed to start HTTP server: %s", err)
		}
	}(d)

	for {
		select {
		// flow was completed or error occured
		case <-d.quitChan:
			log.Debugf("Shutdown signal received. We're done here")

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)

			d.httpServer.Shutdown(ctx)
			cancel()
			log.Infof("Shutdown completed")
			return nil
		// OS signal was received
		case sig := <-d.signalChan:
			close(d.quitChan)
			return fmt.Errorf("signal %d (%s) received. Initiating shutdown", sig, sig)
		default:
		}
	}
}

// initialize the struct, parse commandline flags and install a signal handler
func (d *DexterOIDC) initialize() {
	// install signal handler
	signal.Notify(
		d.signalChan,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	// create random string as CSRF protection for the oauth2 flow
	d.state = utils.RandomString()

	d.clientID = clientID
	d.clientSecret = clientSecret
	d.callback = callback
	d.kubeConfig = kubeConfig
	d.kubeUsername = kubeUsername
	d.dryRun = dryRun
}

// accept callbacks from your browser
func (d *DexterOIDC) callbackHandler(w http.ResponseWriter, r *http.Request) {
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
	if callbackState != d.state {
		log.Error("state mismatch! Someone could be tampering with your connection!")
		http.Error(w, "state mismatch! Someone could be tampering with your connection!", http.StatusBadRequest)
		return
	}

	log.Info("authCode and state verification passed. Fetching JWT")

	// create context and exchange authCode for token
	ctx := oidc.ClientContext(r.Context(), d.httpClient)
	token, err := d.Oauth2Config.Exchange(ctx, code)

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
	d.quitChan <- struct{}{}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<html><body>Authentication completed. It's safe to close this window now ;-)</body></html>"))

	return
}

// write the k8s config
func (d *DexterOIDC) writeK8sConfig(token *oauth2.Token) error {
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

	userIdentifier := customClaim.Email

	if d.kubeUsername != "" {
		userIdentifier = d.kubeUsername
	}

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
		AuthInfos: map[string]*clientCmdApi.AuthInfo{userIdentifier: authInfo},
	}

	// write the rendered config snipped when dry-run is enabled
	if d.dryRun {
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

// initialize the command
func init() {
	kubeConfigDefaultPath := filepath.Join(homedir.HomeDir(), ".kube", "config")

	// add the auth command
	rootCmd.AddCommand(AuthCmd)

	// setup commandline flags
	AuthCmd.PersistentFlags().StringVarP(&clientID, "client-id", "i", "REDACTED", "Google clientID")
	AuthCmd.PersistentFlags().StringVarP(&clientSecret, "client-secret", "s", "REDACTED", "Google clientSecret")
	AuthCmd.PersistentFlags().StringVarP(&callback, "callback", "c", "http://127.0.0.1:64464/callback", "Callback URL. The listen address is dreived from that.")
	AuthCmd.PersistentFlags().StringVarP(&kubeConfig, "kube-config", "k", kubeConfigDefaultPath, "Overwrite the default location of kube config")
	AuthCmd.PersistentFlags().StringVarP(&kubeUsername, "kube-username", "u", "", "Username identifier in the kube config")
	AuthCmd.PersistentFlags().BoolVarP(&dryRun, "dry-run", "d", false, "Toggle config overwrite")
}

// initiate the OIDC flow. This func should be called in each cobra command
func AuthenticateToProvider(provider OIDCProvider) error {
	// attempt to set client credentials with dexter data
	if err := provider.ConfigureOAuth2Manully(); err != nil {
		log.Infof("Fallback to autopilot mode: %s", err)

		if err := provider.Autopilot(); err != nil {
			return fmt.Errorf("failed to configure oauth2 credentials: %s", err)
		}
	}

	// ensure that the required fields and values are sane
	if err := provider.PreflightCheck(); err != nil {
		return fmt.Errorf("failed to complete the provider preflight check: %s", err)
	}

	log.Info("Starting auth browser session. Please check your browser instances...")

	if err := utils.OpenURL(provider.GenerateAuthUrl()); err != nil {
		return fmt.Errorf("failed to open browser session: %s", err)
	}

	log.Info("Spawning http server to receive callbacks")

	// spawn HTTP server
	if err := provider.StartHTTPServer(); err != nil {
		return fmt.Errorf("HTTP server: %s", err)
	}

	return nil
}

// extract relevant authentication data from the given kube config
func ExtractAuthInfo(kubeConfig string) (*clientCmdApi.AuthInfo, error) {
	var clientCfg *clientCmdApi.Config
	var authInfo *clientCmdApi.AuthInfo
	var err error

	if clientCfg, err = utils.ParseKubernetesClientConfig(kubeConfig); err != nil {
		return nil, err
	}

	if authInfo, err = utils.ExtractOIDCAuthProvider(clientCfg); err != nil {
		return nil, err
	}

	return authInfo, nil
}

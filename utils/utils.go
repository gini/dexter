package utils

import (
	"errors"
	"fmt"
	"math/rand"
	"os/exec"
	"runtime"

	"k8s.io/client-go/tools/clientcmd"
	clientCmdApi "k8s.io/client-go/tools/clientcmd/api"
)

// helper to generate a random string
func RandomString() string {
	var letter = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._+")

	b := make([]rune, 64)
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))]
	}
	return string(b)
}

// point browser to the authCode URL
func OpenURL(url string) error {
	var cmd string
	var args []string

	// find the right command for MacOS & Linux
	switch os := runtime.GOOS; os {
	case "darwin":
		cmd = "open"
	case "linux":
		cmd = "xdg-open"
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler"}
	}

	// append url
	args = append(args, url)

	// run command
	err := exec.Command(cmd, args...).Start()

	if err != nil {
		return errors.New(fmt.Sprintf("command '%s' failed: %s", cmd, err))
	}

	return nil
}

// parse the k8s config
func ParseKubernetesClientConfig(kubeConfig string) (*clientCmdApi.Config, error) {
	// initialize the clientConfig and error variables
	var clientCfg *clientCmdApi.Config
	var err error

	// try to load the credentials from the kubeconfig specified on the commandline
	if kubeConfig != "" {
		clientCfg, err = clientcmd.LoadFromFile(kubeConfig)

		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to load kubeconfig from %s: %s", kubeConfig, err))
		}
	} else {
		// try to load credentials from CurrentContext
		clientCfg, err = clientcmd.NewDefaultClientConfigLoadingRules().Load()

		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to load kubeconfig from the default locations: %s", err))
		}
	}

	return clientCfg, nil
}

// find a OIDC provider in the config
func ExtractOIDCAuthProvider(config *clientCmdApi.Config) (*clientCmdApi.AuthInfo, error) {
	// loop through all the contexts until we find the current context
	for contextName, context := range config.Contexts {
		// find the context definition that matches the current active context
		if contextName == config.CurrentContext {
			// loop through the global authentication definitions
			for authName, authInfo := range config.AuthInfos {
				// find the authentication definition that is in use in the current context
				if authName == context.AuthInfo {
					// ensure it is oidc based
					if authInfo.AuthProvider != nil && authInfo.AuthProvider.Name == "oidc" {
						// verify that relevant keys exist
						for _, key := range []string{"client-id", "client-secret", "idp-issuer-url"} {
							if _, ok := authInfo.AuthProvider.Config[key]; !ok {
								return nil, errors.New(fmt.Sprintf("%s is missing in kubeconfig", key))
							}
						}

						return authInfo, nil
					}
				}
			}
		}
	}

	return nil, errors.New("no valid OIDC auth provider found")
}

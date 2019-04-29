# Intro
This fork is adding Okta as an additional Idp.

# dexter

[![Build Status](https://travis-ci.org/gini/dexter.svg?branch=master)](https://travis-ci.org/gini/dexter)

`dexter` is a OIDC (OpenId Connect) helper to create a hassle-free Kubernetes login experience powered by Google or Azure as Identity Provider.
All you need is a properly configured Google or Azure client ID & secret.

## Authentication Flow

`dexter` will open a new browser window and redirect you to your configured Idp. The only interaction you have is the login at your provider and your k8s config is updated automatically.

![dexter flow](/assets/dexter_flow.png?raw=true "dexter flow")

## See dexter in action

![dexter in action](/assets/dexter.gif?raw=true "dexter in action")

## Configuration
### Google credentials

  -  Open [console.developers.google.com](https://console.developers.google.com)
  -  Create new credentials
      - OAuth Client ID
      - Web Application
      - Authorized redirect URIs: http://127.0.0.1:64464/callback

### Or, configure Azure credentials

  -  Open [portal.azure.com](https://portal.azure.com)
  -  Go to App registrations and create a new app
      - Enter reply URI http://127.0.0.1:64464/callback
      - Create secret key
      - Collect application ID (client ID)

### Auto pilot configuration
Dexter also support auto pilot mode. If your existing kubectl context uses one of the supported OIDC-providers, Dexter will try to use the OIDC details from kubeconfig.

## Installation

You can download a prebuilt version from the [Github release section](https://github.com/gini/dexter/releases) or build it yourself:

```
go get -u github.com/gini/dexter
cd $GOPATH/src/github.com/gini/dexter

# Linux
OS=linux make

# MacOS
OS=darwin make
```

It is possible to embed your Google credentials into the resulting binary.

```
CLIENT_ID=abc123.apps.googleusercontent.com CLIENT_SECRET=mySecret OS=linux make
```

## Run dexter

Run `dexter` without a command to access the help screen/intro.

```
❯ ./build/dexter_darwin_amd64
    .___               __
  __| _/____ ___  ____/  |_  ___________
 / __ |/ __ \\  \/  /\   __\/ __ \_  __ \
/ /_/ \  ___/ >    <  |  | \  ___/|  | \/
\____ |\___  >__/\_ \ |__|  \___  >__|
     \/    \/      \/           \/

dexter is a authentication helper for Kubernetes that does the heavy
lifting for SSO (Single Sign On) for Kubernetes.

Usage:
  dexter [command]

Available Commands:
  auth        Authenticate with OIDC provider
  help        Help about any command
  version     Print the version number of dexter

Flags:
  -h, --help      help for dexter
  -v, --verbose   verbose output

Use "dexter [command] --help" for more information about a command.
```

Running `dexter auth` will start the authentication process.

```
 ❯ ./build/dexter_darwin_amd64 auth --help
Use your Google login to get a JWT (JSON Web Token) and update your
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

Usage:
  dexter auth [flags]

Flags:
  -c, --callback string        Callback URL. The listen address is dreived from that. (default "http://127.0.0.1:64464/callback")
  -i, --client-id string       Google clientID (default "REDACTED")
  -s, --client-secret string   Google clientSecret (default "REDACTED")
  -d, --dry-run                Toggle config overwrite
  -e, --endpoint string        OIDC-providers: google or azure (default "google")
  -h, --help                   help for auth
  -k, --kube-config string     Overwrite the default location of kube config (~/.kube/config) (default "/Users/dkerwin/.kube/config")
  -t, --tenant string          Your azure tenant (default "common")

Global Flags:
  -v, --verbose   verbose output
```

## Contribution Guidelines

It's awesome that you consider contributing to `dexter` and it's really simple. Here's how it's done:

  - fork repository on Github
  - create a topic/feature branch
  - push your changes
  - update documentation if necessary
  - open a pull request

## Authors

Initial code was written by [Daniel Kerwin](mailto:daniel@gini.net) & [David González Ruiz](mailto:david@gini.net)

## Acknowledgements

`dexter` was inspired by this [blog post series](https://thenewstack.io/tag/Kubernetes-SSO-series) by [Joel Speed](https://thenewstack.io/author/joel-speed/), [Micah Hausler's k8s-oidc-helper
](https://github.com/micahhausler/k8s-oidc-helper) & [CoreOS dex](https://github.com/coreos/dex).

## License

MIT License. See [License](/LICENSE) for full text.


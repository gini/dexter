# dexter

`dexter` is a OIDC (OpenId Connect) helper to create a hassle-free Kubernetes login experience powered by Google or Azure as Identity Provider.
All you need is a properly configured Google or Azure client ID & secret.

## Supported identity providers

| Identity Provider  | State    |
|--------------------|----------|
|  Google            | complete |
|  Microsoft Azure   | complete |

## Authentication Flow

`dexter` will open a new browser tag/window and redirect you to your configured Idp. The only interaction you have is the login at your provider and your k8s config is updated automatically.

![dexter flow](/assets/dexter_flow.png?raw=true "dexter flow")

## See dexter in action

![dexter in action](/assets/dexter.gif?raw=true "dexter in action")

## OIDCProvider Configuration

Each OpenID Connect provider requires some configuration. This basic
description may not be all you have to do but it worked at the time of
writing.

### Google

  - Open [console.developers.google.com](https://console.developers.google.com)
  - Create new credentials
    - OAuth Client ID
    - Web Application
    - Authorized redirect URIs: http://127.0.0.1:64464/callback

### Microsoft Azure

  - Open [portal.azure.com](https://portal.azure.com)
  - Go to Appregistrations and create a new app
    - Enter reply URI http://127.0.0.1:64464/callback
    - Create secret key
    - Collect  application ID (client ID)

### Auto pilot configuration

`dexter` also support auto pilot mode. If your existing kubectl context uses one of the supported Identity Providers, `dexter` will try to use extract the OIDC data from kubeconfig.

## Installation

You can download a prebuilt version from the [Github release section](https://github.com/gini/dexter/releases) or build it yourself.
The easiest way to get everything set up correctly (e.g. ldflags) is to use [goreleaser](https://goreleaser.com).

```
# cd DEXTER_SOURCE
# goreleaser release --snapshot --rm-dist
• releasing...
• loading config file       file=.goreleaser.yml
• loading environment variables
• getting and validating git state
   • building...               commit=377677a03da17461acf7775519518fb3336e6753 latest tag=v0.4.1
   • pipe skipped              error=disabled during snapshot mode
• parsing tag
• running before hooks
   • running                   hook=go mod tidy
• setting defaults
• snapshotting
   • building snapshot...      version=0.4.2-next
• checking distribution directory
   • --rm-dist is set, cleaning it up
• loading go mod information
• build prerequisites
• writing effective config file
   • writing                   config=dist/config.yaml
• building binaries
   • building                  binary=dist/dexter_darwin_arm64/dexter
   • building                  binary=dist/dexter_darwin_amd64/dexter
   • building                  binary=dist/dexter_linux_amd64/dexter
• universal binaries
   • creating from 2 binaries  binary=dist/dexter_darwin_all/dexter
• archives
   • creating                  archive=dist/dexter_0.4.2-next_Linux_x86_64.tar.gz
   • creating                  archive=dist/dexter_0.4.2-next_Darwin_all.tar.gz
• calculating checksums
• storing release metadata
   • writing                   file=dist/artifacts.json
   • writing                   file=dist/metadata.json
• release succeeded after 8.18s
```

Check `./dist` for the build that matches your platform.

### Embed credentials and template

You can also customize the build and embed client credentails and a default kubectl config into the binary. Again, using `goreleaser` for the build is the easiest approach.
Client credentials are embedded automatically when you set two environment variables.

```
CLIENT_ID=abc123.apps.googleusercontent.com
CLIENT_SECRET=mySecret
```

You can streamline your user experience even more by also specifying a default provider. `dexter auth` will then run the specified provider.
Valid choices are `google` and `azure`.

```
DEFAULT_PROVIDER=google
```

If you want to to change the default config template that is deployed when there is no config on the system you have to replace the contents of `./tmpl/kube-config.yaml` with your valid kubectl configuration.
This can come in handy if you want to pre-populate clusters and certificates.

```
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: XXX
    server: https://stage.cluster:6443
  name: stage
- cluster:
    certificate-authority-data: YYY
    server: https://production.cluster:6443
  name: production
contexts:
- context:
    cluster: stage
    user: {{ .User }}
  name: stage
- context:
    cluster: production
    user: {{ .User }}
  name: production
current-context: stage
kind: Config
preferences: {}
```

Please make sure that you have `{{ .User }}` in all contexts that need you want to enrich with the OIDC account you are about to configure.

## Run dexter

Run `dexter` without a command to access the help screen/intro.

```
❯ ./dexter
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

Running `dexter auth [Idp]` will start the authentication process.

```
 ❯ ./dexter auth --help
Use a provider sub-command to authenticate against your identity provider of choice.
For details go to: https://gini.net/en/blog/frictionless-kubernetes-openid-connect-integration/

Usage:
  dexter auth [flags]
  dexter auth [command]

Available Commands:
  azure       Authenticate with the Microsoft Azure Identity Provider
  google      Authenticate with the Google Identity Provider

Flags:
  -c, --callback string        Callback URL. The listen address is dreived from that. (default "http://127.0.0.1:64464/callback")
  -i, --client-id string       Google clientID (default "REDACTED")
  -s, --client-secret string   Google clientSecret (default "REDACTED")
  -d, --dry-run                Toggle config overwrite
  -h, --help                   help for auth
  -k, --kube-config string     Overwrite the default location of kube config (default "/Users/dkerwin/.kube/config")
  -t, --kube-template          Use the embedded template when there is no kubectl configuration (default true)
  -u, --kube-username string   Username identifier in the kube config
  -f, --write-email string     Write user email to the specified file for use with other tooling

Global Flags:
  -v, --verbose   verbose output

Use "dexter auth [command] --help" for more information about a command.
```

## Contribution Guidelines

It's awesome that you consider contributing to `dexter` and it's really simple. Here's how it's done:

  - fork repository on Github
  - create a topic/feature branch
  - push your changes
  - update documentation if necessary
  - open a pull request

## Authors & Contributors

Initial code was written by [Daniel Kerwin](mailto:daniel@gini.net) & David González Ruiz

Contributors (in alphabetical order):
-   https://github.com/andrewsav-datacom
-   https://github.com/cblims
-   https://github.com/Lujeni
-   https://github.com/pussinboots
-   https://github.com/tillepille

Thank you so much!

## Acknowledgements

`dexter` was inspired by this [blog post series](https://thenewstack.io/tag/Kubernetes-SSO-series) by [Joel Speed](https://thenewstack.io/author/joel-speed/), [Micah Hausler's k8s-oidc-helper
](https://github.com/micahhausler/k8s-oidc-helper) & [CoreOS dex](https://github.com/coreos/dex).

## License

MIT License. See [License](/LICENSE) for full text.


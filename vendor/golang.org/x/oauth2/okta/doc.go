// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// please read https://developer.okta.com/docs/api/resources/oidc/

// Package okta provides support for making OAuth2 authorized and authenticated
// HTTP requests to an OKTA OIDC app. It supports OKTA's OIDC Web server implicit id_token flow

// OAuth2 Configs
//

// dexter leverages the embedded client id and secret in auth#initialize, sat here as envars OKTA_OIDC_CLIENT_ID and OKTA_OIDC_CLIENT_SECRET;
// if absent, it attempts config from the current kubectl context in kubeconfig.

// In order to ascertain the corrrect Okta endpoint, dexter relies upon the OKTA_SUBDOMAIN envar:
// e.g., if the endpoint is foobar.okta.com, `export OKTA_SUBDOMAIN=foobar` (or prefox the run command accordingly).

// The repo-root-based run commandline  is:
//          `./build/dexter_darwin_amd64 -e okta auth -d -c http://127.0.0.1:5533/callback`
//

// for kubernetes RBAC authentication, the kube-apiserver manifest should include these lines in the containers/command/kube-apiserver stanza:
//  - --oidc-issuer-url=https://OKTA_SUBDOMAIN.okta.com
//  - --oidc-client-id=OKTA_OIDC_CLIENT_ID
//  - --oidc-username-claim=email # if desired
//  - --oidc-groups-claim=groups  # if desired
// with the envar names replaced appropriately.

package okta // import "golang.org/x/oauth2/okta"

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

// The repo-root-based run commandline  is:
//          `./build/dexter_darwin_amd64 -e okta auth -d -c http://127.0.0.1:5533/callback`
//
package okta // import "golang.org/x/oauth2/okta"

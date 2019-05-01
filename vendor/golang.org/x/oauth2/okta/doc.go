// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// please read: https://developer.okta.com/docs/api/resources/oidc/
//							https://developer.okta.com/authentication-guide/implementing-authentication/set-up-authz-server/
// Package okta provides support for making OAuth2 authorized and authenticated
// HTTP requests to an OKTA OIDC app associated with an OKTA Authorization Server.
// With the correct configuration, it will fetch a fat id_token, i.e. one containing groups and/or other specified attributes;
// the groups attribute can be leveraged in Kubernetes RBAC for groujp-based rolebindings.

// OAuth2 Configs
//
// The Makefile embeds credentials from environment variables so that the executable con be distributed without reliance on the user's envir.
// These must be set:
//		OKTA_OIDC_CLIENT_ID
//		OKTA_OIDC_CLIENT_SECRET
//		OKTA_OIDC_CALLBACK
//		OKTA_OIDC_ENDPOINT

// The Makefile creates cmd/kubeauth, and creats and uses ./tmp for temporary storage of the non-embedded source files
// usage:
//		bin/kubeauth auth [dexter options]
//

// In addition to the Okta docs cited above, see the exellent setup docs for jetstack/okta-kubectl-auth: https://github.com/jetstack/okta-kubectl-auth/blob/master/docs/okta-setup.md
// i.e., in the kube-apiserver manifest, add:
//   --oidc-issuer-url=[okta application server url]
//   --oidc-client-id=[okta oidc app client_id]
//   --oidc-username-claim=preferred_username
//   --oidc-username-prefix=okta:
//   --oidc-groups-claim=groups
//   --oidc-groups-prefix=okta:

package okta // import "golang.org/x/oauth2/okta"

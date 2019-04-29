// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package okta // import "golang.org/x/oauth2/okta"

import (
	"os"
	"strings"

	"golang.org/x/oauth2"
)

// var auth_url = strings.Join([]string{"https://", os.Getenv("OKTA_DOMAIN"), ".okta.com/oauth2/v1/authorize"}, "")
// var token_url = strings.Join([]string{"https://", os.Getenv("OKTA_DOMAIN"), ".okta.com/oauth2/v1/token"}, "")
// var client_id = string(os.Getenv("OKTA_CLIENT_ID"))
// var client_secret = string(os.Getenv("OKTA_CLIENT_SECRET"))
// var redirect_urls = []string(os.Getenv("OKTA_REDIRECT_URIS"))
// var scope = string(os.Getenv("OKTA_SCOPE"))

// LiveConnectEndpoint is Windows's Live ID OAuth 2.0 endpoint.
// var LiveConnectEndpoint = oauth2.Endpoint{
// // AuthURL:  "https://login.live.com/oauth20_authorize.srf",
// // TokenURL: "https://login.live.com/oauth20_token.srf",
// AuthURL:  strings.Join([]string{"https://", os.Getenv("OKTA_DOMAIN"), ".okta.com/oauth2/v1/authorize"}, ""),
// TokenURL: strings.Join([]string{"https://", os.Getenv("OKTA_DOMAIN"), ".okta.com/oauth2/v1/token"}, ""),
// }

var Endpoint = oauth2.Endpoint{
	AuthURL:  strings.Join([]string{"https://", os.Getenv("OKTA_SUBDOMAIN"), ".okta.com/oauth2/v1/authorize"}, ""),
	TokenURL: strings.Join([]string{"https://", os.Getenv("OKTA_SUBDOMAIN"), ".okta.com/oauth2/v1/token"}, ""),
}

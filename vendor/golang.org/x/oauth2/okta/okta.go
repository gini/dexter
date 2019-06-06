// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package okta // import "golang.org/x/oauth2/okta"

import (
	"strings"

	"golang.org/x/oauth2"
)

var Endpoint = oauth2.Endpoint{
	AuthURL:  strings.Join([]string{"https://asapp-eng.okta.com/oauth2/ausfe4bckxltltnik356", "/v1/authorize"}, ""),
	TokenURL: strings.Join([]string{"https://asapp-eng.okta.com/oauth2/ausfe4bckxltltnik356", "/v1/token"}, ""),
}

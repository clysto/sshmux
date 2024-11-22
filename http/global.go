package http

import (
	"sshmux/common"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type SsoProvider struct {
	Name     string
	Label    string
	Config   oauth2.Config
	Provider *oidc.Provider
	Verifier *oidc.IDTokenVerifier
}

var api *common.API

var ssoProviders []*SsoProvider

var sshpiperHost string
var sshpiperPort int

var recordingsDir string
var targetHealths []common.TargetHealth

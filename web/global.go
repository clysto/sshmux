package main

import (
	"sshmux/sshmux"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var api *sshmux.API
var ssoConfig oauth2.Config
var ssoProvider *oidc.Provider
var ssoVerifier *oidc.IDTokenVerifier
var ssoLabel string

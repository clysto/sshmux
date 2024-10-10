package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"path/filepath"
	"sshmux/sshmux"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/foolin/goview"
	"github.com/foolin/goview/supports/ginview"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

//go:embed templates/*
var templatesFS embed.FS

func embeddedFH(config goview.Config, tmpl string) (string, error) {
	path := filepath.Join(config.Root, tmpl)
	bytes, err := templatesFS.ReadFile(path + config.Extension)
	return string(bytes), err
}

func main() {
	port := flag.String("port", "7878", "Server port to listen on")
	externalURL := flag.String("external-host", "", "External URL")
	clientID := flag.String("client-id", "", "OIDC Client ID")
	clientSecret := flag.String("client-secret", "", "OIDC Client Secret")
	issuerURL := flag.String("issuer-url", "", "OIDC Issuer URL")
	scopes := flag.String("scopes", "openid,profile,email", "OIDC scopes (comma-separated)")
	oidcLabel := flag.String("sso-label", "SSO", "SSO label")
	dbPath := flag.String("db", "sshmux.db", "Path to the SQLite database")

	flag.Parse()

	ssoLabel = *oidcLabel

	var err error
	api, err = sshmux.NewAPI(*dbPath)
	if err != nil {
		panic(err)
	}

	// 解析 scopes 参数为 []string
	scopeList := strings.Split(*scopes, ",")

	ssoProvider, err = oidc.NewProvider(context.Background(), *issuerURL)
	if err != nil {
		panic(err)
	}
	ssoConfig = oauth2.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		Endpoint:     ssoProvider.Endpoint(),
		RedirectURL:  fmt.Sprintf("%s/auth/callback", *externalURL),
		Scopes:       scopeList,
	}
	ssoVerifier = ssoProvider.Verifier(&oidc.Config{ClientID: "sshmux"})

	app := gin.Default()

	gv := ginview.New(goview.Config{
		Root:         "templates",
		Extension:    ".tmpl",
		Master:       "layout",
		DisableCache: true,
	})

	gv.SetFileHandler(embeddedFH)

	app.HTMLRender = gv

	app.GET("/", Home)
	app.GET("/login", Login)
	app.GET("/logout", Logout)
	app.GET("/admin", Auth(true), Admin)
	app.GET("/account", Auth(false), Account)
	app.GET("/auth/callback", AuthCallback)
	app.POST("/pubkey", Auth(false), CreatePubkey)
	app.POST("/pubkey/delete/:id", Auth(false), DeletePubkey)
	app.POST("/target", Auth(true), CreateTarget)
	app.POST("/target/delete/:id", Auth(true), DeleteTarget)
	app.POST("/target/update/:id", Auth(true), UpdateTarget)
	app.Run(fmt.Sprintf("0.0.0.0:%s", *port))
}

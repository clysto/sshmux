package http

import (
	"context"
	"embed"
	"encoding/gob"
	"fmt"
	"html/template"
	"path/filepath"
	"sshmux/common"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dustin/go-humanize"
	"github.com/foolin/goview"
	"github.com/foolin/goview/supports/ginview"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
)

//go:embed templates/*
var templatesFS embed.FS

func embeddedFH(config goview.Config, tmpl string) (string, error) {
	path := filepath.Join(config.Root, tmpl)
	bytes, err := templatesFS.ReadFile(path + config.Extension)
	return string(bytes), err
}

func RunServer(cCtx *cli.Context) error {
	configPath := cCtx.String("config")
	config, err := common.LoadConfig(configPath)
	if err != nil {
		return err
	}
	sshpiperHost = config.SSHHost
	sshpiperPort = config.SSHPort

	// Config SSO providers
	for _, ssoConfig := range config.SSOProviders {
		provider, err := oidc.NewProvider(context.Background(), ssoConfig.IssuerURL)
		if err != nil {
			return err
		}
		ssoProviders = append(ssoProviders, &SsoProvider{
			Name:  ssoConfig.Name,
			Label: ssoConfig.Label,
			Config: oauth2.Config{
				ClientID:     ssoConfig.ClientID,
				ClientSecret: ssoConfig.ClientSecret,
				Endpoint:     provider.Endpoint(),
				RedirectURL:  fmt.Sprintf("%s/auth/callback", config.ExternalURL),
				Scopes:       ssoConfig.Scopes,
			},
			Provider: provider,
			Verifier: provider.Verifier(&oidc.Config{ClientID: ssoConfig.ClientID}),
		})
	}

	// Config API
	api, err = common.NewAPI(config.DB)
	if err != nil {
		return err
	}

	// Start the web server
	app := gin.Default()
	gob.Register(common.User{})
	sessionStore := memstore.NewStore([]byte(config.SessionSecret))
	sessionStore.Options(sessions.Options{
		MaxAge: 1800, // 30 minutes
	})
	app.Use(sessions.Sessions("sshmux", sessionStore))

	gv := ginview.New(goview.Config{
		Root:         "http/templates",
		Extension:    ".tmpl",
		Master:       "layout",
		DisableCache: true,
		Funcs: template.FuncMap{
			"duration": humanize.Time,
		},
	})

	// gv.SetFileHandler(embeddedFH)

	app.HTMLRender = gv

	app.Use(Auth())

	app.GET("/", RequireLogin(), Home)
	app.GET("/login", Login)
	app.GET("/logout", Logout)
	app.GET("/admin", RequireAdmin(), Admin)
	app.GET("/account", RequireLogin(), Account)
	app.GET("/auth/callback", AuthCallback)
	app.GET("/username", ChangeUserName)

	app.POST("/login", Login)
	app.POST("/pubkey", RequireLogin(), CreatePubkey)
	app.POST("/pubkey/delete/:id", RequireLogin(), DeletePubkey)
	app.POST("/target", RequireAdmin(), CreateTarget)
	app.POST("/target/delete/:id", RequireAdmin(), DeleteTarget)
	app.POST("/target/update/:id", RequireAdmin(), UpdateTarget)
	app.POST("/username", ChangeUserName)

	app.NoRoute(HandleNotFound)

	return app.Run(fmt.Sprintf("0.0.0.0:%d", config.Port))
}

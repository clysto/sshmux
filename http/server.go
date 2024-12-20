package http

import (
	"context"
	"embed"
	"encoding/gob"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"sshmux/common"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dustin/go-humanize"
	"github.com/foolin/goview"
	"github.com/foolin/goview/supports/ginview"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"
	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
)

//go:embed templates/*
var templatesFS embed.FS

//go:embed assets/*
var assetsFS embed.FS

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
	recordingsDir = config.RecordingsDir

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

	// Start the cron job
	c := cron.New()
	c.AddFunc("@daily", func() {
		api.DeleteOldRecordings(time.Now().AddDate(0, 0, -config.RecordingsRetentionDays), config.RecordingsDir)
	})
	api.CheckTargetHealth(&targetHealths)
	c.AddFunc("*/10 * * * *", func() {
		api.CheckTargetHealth(&targetHealths)
	})
	c.Start()

	// Start the web server
	app := gin.Default()
	gob.Register(common.User{})
	sessionStore := memstore.NewStore([]byte(config.SessionSecret))
	sessionStore.Options(sessions.Options{
		MaxAge: 1800, // 30 minutes
	})
	app.Use(sessions.Sessions("sshmux", sessionStore))

	gv := ginview.New(goview.Config{
		Root:         "templates",
		Extension:    ".tmpl",
		Master:       "layout",
		DisableCache: true,
		Funcs: template.FuncMap{
			"duration": humanize.Time,
			"sub": func(a, b int) int {
				return a - b
			},
			"seq": func(n int) []int {
				seq := make([]int, n)
				for i := range seq {
					seq[i] = i
				}
				return seq
			},
		},
	})

	gv.SetFileHandler(embeddedFH)

	app.HTMLRender = gv

	app.Use(Auth())

	app.StaticFS("/static", http.FS(assetsFS))

	app.GET("/", RequireLogin(), Home)
	app.GET("/login", Login)
	app.GET("/logout", Logout)
	app.GET("/admin", RequireAdmin(), Admin)
	app.GET("/account", RequireLogin(), Account)
	app.GET("/auth/callback", AuthCallback)
	app.GET("/username", ChangeUserName)
	app.GET("/recordings/:id", RequireAdmin(), RecordingPage)
	app.GET("/recordings/cast/:id/:channel", RequireAdmin(), HandleRecording)

	app.POST("/login", Login)
	app.POST("/pubkey", RequireLogin(), CreatePubkey)
	app.POST("/pubkey/delete/:id", RequireLogin(), DeletePubkey)
	app.POST("/target", RequireAdmin(), CreateTarget)
	app.POST("/target/delete/:id", RequireAdmin(), DeleteTarget)
	app.POST("/target/update/:id", RequireAdmin(), UpdateTarget)
	app.POST("/user/delete/:id", RequireAdmin(), DeleteUser)
	app.POST("/username", ChangeUserName)

	app.NoRoute(HandleNotFound)

	return app.Run(fmt.Sprintf("0.0.0.0:%d", config.Port))
}

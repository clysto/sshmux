package http

import (
	"context"
	"embed"
	"encoding/gob"
	"fmt"
	"html/template"
	"net"
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
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

//go:embed templates/*
var templatesFS embed.FS

//go:embed assets/*
var assetsFS embed.FS

type SsoProvider struct {
	Name     string
	Label    string
	Config   oauth2.Config
	Provider *oidc.Provider
	Verifier *oidc.IDTokenVerifier
}

type HTTPServer struct {
	app           *gin.Engine
	port          int
	host          string
	sshpiperHost  string
	sshpiperPort  int
	recordingsDir string
	api           *common.API
	ssoProviders  []*SsoProvider
	targetHealths []common.TargetHealth
	cronManager   *cron.Cron
}

func embeddedFH(config goview.Config, tmpl string) (string, error) {
	path := filepath.Join(config.Root, tmpl)
	bytes, err := templatesFS.ReadFile(path + config.Extension)
	return string(bytes), err
}

func NewServer(config *common.Config) (*HTTPServer, error) {
	gin.SetMode(gin.ReleaseMode)

	server := &HTTPServer{
		port: config.HTTPPort,
		host: config.Host,
	}

	server.sshpiperHost = config.ExternalSSHHost
	server.sshpiperPort = config.SSHPort
	server.recordingsDir = config.RecordingsDir

	// Config SSO providers
	for _, ssoConfig := range config.SSOProviders {
		provider, err := oidc.NewProvider(context.Background(), ssoConfig.IssuerURL)
		if err != nil {
			return nil, err
		}
		server.ssoProviders = append(server.ssoProviders, &SsoProvider{
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
	var err error
	server.api, err = common.NewAPI(config.DB)
	if err != nil {
		return nil, err
	}

	// Config the cron job
	server.cronManager = cron.New()
	server.cronManager.AddFunc("@daily", func() {
		server.api.DeleteOldRecordings(time.Now().AddDate(0, 0, -config.RecordingsRetentionDays), config.RecordingsDir)
	})
	server.api.CheckTargetHealth(&server.targetHealths)
	server.cronManager.AddFunc("*/10 * * * *", func() {
		server.api.CheckTargetHealth(&server.targetHealths)
	})

	// Create the web server
	server.app = gin.New()
	server.app.Use(gin.Recovery())
	gob.Register(common.User{})
	sessionStore := memstore.NewStore([]byte(config.SessionSecret))
	sessionStore.Options(sessions.Options{
		MaxAge: 1800, // 30 minutes
	})
	server.app.Use(sessions.Sessions("sshmux", sessionStore))

	gv := ginview.New(goview.Config{
		Root:         "../http/templates",
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

	// gv.SetFileHandler(embeddedFH)

	server.app.HTMLRender = gv

	server.app.Use(Auth())

	server.app.StaticFS("/static", http.FS(assetsFS))

	server.app.GET("/", RequireLogin(), server.Home)
	server.app.GET("/login", server.Login)
	server.app.GET("/logout", server.Logout)
	server.app.GET("/admin", RequireAdmin(), server.Admin)
	server.app.GET("/keys", RequireLogin(), server.Keys)
	server.app.GET("/auth/callback", server.AuthCallback)
	server.app.GET("/username", server.ChangeUserName)
	server.app.GET("/recordings/:id", RequireAdmin(), server.RecordingPage)
	server.app.GET("/recordings/cast/:id/:channel", RequireAdmin(), server.HandleRecording)

	server.app.POST("/login", server.Login)
	server.app.POST("/pubkey", RequireLogin(), server.CreatePubkey)
	server.app.POST("/pubkey/delete/:id", RequireLogin(), server.DeletePubkey)
	server.app.POST("/target", RequireAdmin(), server.CreateTarget)
	server.app.POST("/target/delete/:id", RequireAdmin(), server.DeleteTarget)
	server.app.POST("/target/update/:id", RequireAdmin(), server.UpdateTarget)
	server.app.POST("/user/delete/:id", RequireAdmin(), server.DeleteUser)
	server.app.POST("/username", server.ChangeUserName)

	server.app.NoRoute(HandleNotFound)
	return server, nil
}

func (s *HTTPServer) Start() error {
	s.cronManager.Start()
	addr := net.JoinHostPort(s.host, fmt.Sprintf("%d", s.port))
	log.Infof("http server listening on %s\n", addr)
	s.app.Run(addr)
	return nil
}

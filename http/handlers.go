package http

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
	"regexp"
	"sshmux/common"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func (s *HTTPServer) Home(c *gin.Context) {
	query := c.Query("q")
	var targets []common.Target
	if query != "" {
		targets = s.api.SearchTargets(query)
	} else {
		targets = s.api.ListTargets()
	}

	now := time.Now()
	uptime := make(map[uint][]common.TargetHealth)
	for _, health := range s.targetHealths {
		if now.Sub(health.Time) < 300*time.Minute {
			uptime[health.TargetID] = append(uptime[health.TargetID], health)
		}
	}

	// only show latest 20 health checks
	for id, healths := range uptime {
		if len(healths) > 20 {
			uptime[id] = healths[len(healths)-20:]
		}
	}

	ReturnHTML(c, "index", gin.H{
		"targets":      targets,
		"sshpiperHost": s.sshpiperHost,
		"sshpiperPort": s.sshpiperPort,
		"uptime":       uptime,
	})
}

func (s *HTTPServer) Login(c *gin.Context) {
	session := sessions.Default(c)
	if c.Request.Method == "GET" {
		// Generate a random oidc state
		state := RandState()
		session.Set("oauth_state", state)

		var ssos []gin.H
		// Add the SSO providers to the HTML page
		for _, sso := range s.ssoProviders {
			ssos = append(ssos, gin.H{
				"label": sso.Label,
				"url":   sso.Config.AuthCodeURL(fmt.Sprintf("%s-%s", sso.Name, state)),
			})
		}

		errorFlashes := session.Flashes("error")
		session.Save()

		ReturnHTML(c, "login", gin.H{
			"ssos":   ssos,
			"errors": errorFlashes,
		})
	} else if c.Request.Method == "POST" {
		username := c.PostForm("username")
		password := c.PostForm("password")

		user, err := s.api.Login(username, password)
		if err != nil {
			session.AddFlash("Invalid username or password.", "error")
			session.Save()
			c.Redirect(http.StatusFound, "/login")
			return
		}

		session.Set("user", *user)
		session.Save()

		c.Redirect(http.StatusFound, "/")
	}
}

func (s *HTTPServer) Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusFound, "/")
}

func (s *HTTPServer) Keys(c *gin.Context) {
	user := c.MustGet("user").(common.User)
	keys := s.api.GetPubkeysByUserID(user.ID)

	latestKeyID := -1
	latestUsedAt := time.Time{}
	for _, key := range keys {
		if key.UsedAt.After(latestUsedAt) {
			latestUsedAt = key.UsedAt
			latestKeyID = int(key.ID)
		}
	}

	ReturnHTML(c, "keys", gin.H{
		"user":    user,
		"pubkeys": keys,
		"latest":  latestKeyID,
	})
}

func (s *HTTPServer) AuthCallback(c *gin.Context) {
	session := sessions.Default(c)

	returnedState := c.Query("state")
	code := c.Query("code")

	storedState := session.Get("oauth_state").(string)

	seps := strings.Split(returnedState, "-")
	if len(seps) != 2 {
		ReturnError(c, http.StatusBadRequest, "Invalid state parameter")
		return
	}

	ssoName := seps[0]
	returnedState = seps[1]

	if returnedState != storedState {
		ReturnError(c, http.StatusBadRequest, "Invalid state parameter")
		return
	}

	var ssoProvider *SsoProvider
	for _, sso := range s.ssoProviders {
		if ssoName == sso.Name {
			ssoProvider = sso
			break
		}
	}

	if ssoProvider == nil {
		ReturnError(c, http.StatusBadRequest, "Invalid state parameter")
		return
	}

	token, err := ssoProvider.Config.Exchange(context.Background(), code)
	if err != nil {
		ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to exchange token: %v", err))
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		ReturnError(c, http.StatusBadRequest, "No id_token field in oauth2 token")
		return
	}

	// Verify ID Token
	idToken, err := ssoProvider.Verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		c.Next()
		return
	}
	var claims struct {
		PreferredUsername string `json:"preferred_username"`
		Subject           string `json:"sub"`
		Email             string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		c.Next()
		return
	}

	// Find or create the user
	user := s.api.GetUserBySSO(ssoName, claims.Subject)
	if user == nil {
		// First time login
		user = &common.User{
			Username: claims.PreferredUsername,
			IsAdmin:  false,
			SSOCredentials: []common.SSOCredential{
				{
					ProviderName: ssoName,
					Subject:      claims.Subject,
				},
			},
			LastLoginAt: time.Now(),
		}
		session.Set("creatingUser", *user)
		session.Save()
		c.Redirect(http.StatusFound, "/username")
		return
	}

	session.Set("user", *user)
	session.Save()

	c.Redirect(http.StatusFound, "/")
}

func (s *HTTPServer) CreatePubkey(c *gin.Context) {
	user := c.MustGet("user").(common.User)
	key := c.PostForm("publicKey")

	err := s.api.CreatePubkey(common.Pubkey{
		UserID: user.ID,
		Key:    key,
	})
	if err != nil {
		ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to create pubkey: %v", err))
		return
	}

	c.Redirect(http.StatusFound, "/keys")
}

func (s *HTTPServer) DeletePubkey(c *gin.Context) {
	user := c.MustGet("user").(common.User)

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		ReturnError(c, http.StatusBadRequest, "Invalid pubkey ID")
		return
	}
	key := s.api.GetPubkeyById(id)
	if key == nil || key.UserID != user.ID {
		ReturnError(c, http.StatusBadRequest, "Invalid pubkey ID")
		return
	}
	err = s.api.DeletePubkeyById(id)
	if err != nil {
		ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to delete pubkey: %v", err))
		return
	}
	c.Redirect(http.StatusFound, "/keys")
}

func (s *HTTPServer) Admin(c *gin.Context) {
	tab := c.Query("tab")

	if tab != "recordings" && tab != "targets" && tab != "users" {
		tab = "targets"
	}

	switch tab {
	case "recordings":
		page, err := strconv.Atoi(c.Query("page"))
		if err != nil {
			page = 1
		}
		// 获取搜索查询参数
		user := c.Query("user")
		target := c.Query("target")
		// 获取时间范围参数
		var after, before *time.Time
		afterStr := c.Query("after")
		beforeStr := c.Query("before")

		// 解析时间字符串为 time.Time 类型
		if afterStr != "" {
			parsedAfter, err := time.Parse("2006-01-02", afterStr)
			if err == nil {
				after = &parsedAfter
			} else {
				afterStr = ""
			}
		}

		if beforeStr != "" {
			parsedBefore, err := time.Parse("2006-01-02", beforeStr)
			if err == nil {
				before = &parsedBefore
			} else {
				beforeStr = ""
			}
		}

		recordings, hasNext := s.api.SearchRecordings(30, page, user, target, after, before)
		ReturnHTML(c, "admin", gin.H{
			"recordings": recordings,
			"hasPrev":    page > 1,
			"hasNext":    hasNext,
			"prevPage":   page - 1,
			"nextPage":   page + 1,
			"search": gin.H{
				"user":   user,
				"target": target,
				"after":  afterStr,
				"before": beforeStr,
			},
			"tab": tab,
		})
	case "targets":
		targets := s.api.ListTargets()
		ReturnHTML(c, "admin", gin.H{
			"targets": targets,
			"tab":     tab,
		})
	case "users":
		page, err := strconv.Atoi(c.Query("page"))
		if err != nil {
			page = 1
		}
		users, hasNext := s.api.ListUsers(30, page)
		ReturnHTML(c, "admin", gin.H{
			"tab":      tab,
			"users":    users,
			"hasPrev":  page > 1,
			"hasNext":  hasNext,
			"prevPage": page - 1,
			"nextPage": page + 1,
		})
	}
}

func (s *HTTPServer) RecordingPage(c *gin.Context) {
	id := c.Param("id")
	recording := s.api.GetRecordingById(id)
	if recording == nil {
		ReturnError(c, http.StatusBadRequest, "Invalid recording ID")
		return
	}
	var channels []string
	if recording.Status == 0 {
		dir := path.Join(s.recordingsDir, recording.RecordID)
		files, err := os.ReadDir(dir)
		if err != nil {
			ReturnError(c, http.StatusBadRequest, "Failed to list channel files")
			return
		}
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			channels = append(channels, file.Name())
		}
	}
	ReturnHTML(c, "recording", gin.H{
		"recording": recording,
		"channels":  channels,
	})
}

func (s *HTTPServer) CreateTarget(c *gin.Context) {
	name := c.PostForm("name")
	host := c.PostForm("host")
	port, err := strconv.Atoi(c.PostForm("port"))
	if err != nil {
		ReturnError(c, http.StatusBadRequest, "Invalid port")
		return
	}
	user := c.PostForm("user")
	desc := c.PostForm("description")

	err = s.api.CreateTarget(common.Target{
		Name:        name,
		Host:        host,
		Port:        int32(port),
		User:        user,
		Description: desc,
	})
	if err != nil {
		ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to create target: %v", err))
		return
	}

	c.Redirect(http.StatusFound, "/admin")
}

func (s *HTTPServer) UpdateTarget(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		ReturnError(c, http.StatusBadRequest, "Invalid pubkey ID")
		return
	}

	name := c.PostForm("name")
	host := c.PostForm("host")
	port, err := strconv.Atoi(c.PostForm("port"))
	if err != nil {
		ReturnError(c, http.StatusBadRequest, "Invalid port")
		return
	}
	user := c.PostForm("user")
	desc := c.PostForm("description")

	target := s.api.GetTargetById(id)
	if target == nil {
		ReturnError(c, http.StatusBadRequest, "Invalid target ID")
		return
	}
	target.Name = name
	target.Host = host
	target.Port = int32(port)
	target.User = user
	target.Description = desc

	err = s.api.UpdateTarget(*target)
	if err != nil {
		ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to update target: %v", err))
		return
	}

	c.Redirect(http.StatusFound, "/admin")
}

func (s *HTTPServer) DeleteTarget(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		ReturnError(c, http.StatusBadRequest, "Invalid pubkey ID")
		return
	}
	err = s.api.DeleteTargetId(id)
	if err != nil {
		ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to delete target: %v", err))
		return
	}
	c.Redirect(http.StatusFound, "/admin?tab=targets")
}

func (s *HTTPServer) DeleteUser(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		ReturnError(c, http.StatusBadRequest, "Invalid user ID")
		return
	}
	user := s.api.GetUserById(id)
	if user == nil || user.IsAdmin {
		ReturnError(c, http.StatusBadRequest, "Cannot delete user")
		return
	}
	err = s.api.DeleteUserById(id)
	if err != nil {
		ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to delete user: %v", err))
		return
	}
	c.Redirect(http.StatusFound, "/admin?tab=users")
}

func (s *HTTPServer) ChangeUserName(c *gin.Context) {
	session := sessions.Default(c)
	creating := false
	var user common.User
	if session.Get("creatingUser") != nil {
		user = session.Get("creatingUser").(common.User)
		creating = true
	} else {
		v, ok := c.Get("user")
		if !ok {
			ReturnError(c, http.StatusBadRequest, "Invalid user")
			return
		}
		user = v.(common.User)
	}

	if c.Request.Method == "GET" {
		errorFlashes := session.Flashes("error")
		session.Save()
		ReturnHTML(c, "username", gin.H{
			"user":   user,
			"errors": errorFlashes,
		})
	} else if c.Request.Method == "POST" {
		username := c.PostForm("username")
		if username == "" {
			session.AddFlash("Username cannot be empty.", "error")
			session.Save()
			c.Redirect(http.StatusFound, "/username")
			return
		}

		user.Username = username

		r := regexp.MustCompile("^[a-zA-Z0-9_]{3,20}$")
		if !r.MatchString(username) {
			session.AddFlash("Username must be between 3 and 20 characters and only contain alphanumeric characters and underscore.", "error")
			session.Save()
			c.Redirect(http.StatusFound, "/username")
			return
		}

		// check if username is already taken
		if s.api.UserExists(username) {
			session.AddFlash("Username is already taken.", "error")
			session.Save()
			c.Redirect(http.StatusFound, "/username")
			return
		}

		if creating {
			err := s.api.CreateUser(user)
			if err != nil {
				ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to create user: %v", err))
				return
			}
			session.Delete("creatingUser")
		} else {
			err := s.api.UpdateUser(user)
			if err != nil {
				ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to update user: %v", err))
				return
			}
		}

		user = *s.api.GetUserByName(user.Username)

		session.Set("user", user)
		session.Save()

		c.Redirect(http.StatusFound, "/keys")
	}
}

func HandleNotFound(c *gin.Context) {
	if strings.HasPrefix(c.Request.URL.Path, "/static") {
		c.Status(http.StatusNotFound)
		c.Abort()
		return
	}
	ReturnError(c, http.StatusNotFound, "Page not found")
}

func (s *HTTPServer) HandleRecording(c *gin.Context) {
	id := c.Param("id")
	channel := c.Param("channel")
	http.ServeFile(c.Writer, c.Request, path.Join(s.recordingsDir, id, channel))
}

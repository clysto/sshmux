package http

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sshmux/common"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func Home(c *gin.Context) {
	query := c.Query("q")
	var targets []common.Target
	if query != "" {
		targets = api.SearchTargets(query)
	} else {
		targets = api.ListTargets()
	}
	ReturnHTML(c, "index", gin.H{
		"targets":      targets,
		"sshpiperHost": sshpiperHost,
		"sshpiperPort": sshpiperPort,
	})
}

func Login(c *gin.Context) {
	session := sessions.Default(c)
	if c.Request.Method == "GET" {
		// Generate a random oidc state
		state := RandState()
		session.Set("oauth_state", state)

		var ssos []gin.H
		// Add the SSO providers to the HTML page
		for _, sso := range ssoProviders {
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

		user, err := api.Login(username, password)
		if err != nil {
			session.AddFlash("Invalid username or password.", "error")
			session.Save()
			c.Redirect(http.StatusFound, "/login")
			return
		}

		session.Set("user", *user)
		session.Save()

		c.Redirect(http.StatusFound, "/account")
	}
}

func Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusFound, "/")
}

func Account(c *gin.Context) {
	user := c.MustGet("user").(common.User)
	keys := api.GetPubkeysByUserID(user.ID)

	latestKeyID := -1
	latestUsedAt := time.Time{}
	for _, key := range keys {
		if key.UsedAt.After(latestUsedAt) {
			latestUsedAt = key.UsedAt
			latestKeyID = int(key.ID)
		}
	}

	ReturnHTML(c, "account", gin.H{
		"user":    user,
		"pubkeys": keys,
		"latest":  latestKeyID,
	})
}

func AuthCallback(c *gin.Context) {
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
	for _, sso := range ssoProviders {
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
	user := api.GetUserBySSO(ssoName, claims.Subject)
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
		}
		session.Set("creatingUser", *user)
		session.Save()
		c.Redirect(http.StatusFound, "/username")
		// err := api.CreateUser(*user)
		// if err != nil {
		// 	ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to create user: %v", err))
		// 	return
		// }
	}

	session.Set("user", *user)
	session.Save()

	c.Redirect(http.StatusFound, "/account")
}

func CreatePubkey(c *gin.Context) {
	user := c.MustGet("user").(common.User)
	key := c.PostForm("publicKey")

	err := api.CreatePubkey(common.Pubkey{
		UserId: user.ID,
		Key:    key,
	})
	if err != nil {
		ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to create pubkey: %v", err))
		return
	}

	c.Redirect(http.StatusFound, "/account")
}

func DeletePubkey(c *gin.Context) {
	user := c.MustGet("user").(common.User)

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		ReturnError(c, http.StatusBadRequest, "Invalid pubkey ID")
		return
	}
	key := api.GetPubkeyById(id)
	if key == nil || key.UserId != user.ID {
		ReturnError(c, http.StatusBadRequest, "Invalid pubkey ID")
		return
	}
	err = api.DeletePubkeyById(id)
	if err != nil {
		ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to delete pubkey: %v", err))
		return
	}
	c.Redirect(http.StatusFound, "/account")
}

func Admin(c *gin.Context) {
	targets := api.ListTargets()
	ReturnHTML(c, "admin", gin.H{
		"targets": targets,
	})
}

func CreateTarget(c *gin.Context) {
	name := c.PostForm("name")
	host := c.PostForm("host")
	port, err := strconv.Atoi(c.PostForm("port"))
	if err != nil {
		ReturnError(c, http.StatusBadRequest, "Invalid port")
		return
	}
	user := c.PostForm("user")

	err = api.CreateTarget(common.Target{
		Name: name,
		Host: host,
		Port: int32(port),
		User: user,
	})
	if err != nil {
		ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to create target: %v", err))
		return
	}

	c.Redirect(http.StatusFound, "/admin")
}

func UpdateTarget(c *gin.Context) {
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

	target := api.GetTargetById(id)
	if target == nil {
		ReturnError(c, http.StatusBadRequest, "Invalid target ID")
		return
	}
	target.Name = name
	target.Host = host
	target.Port = int32(port)
	target.User = user

	err = api.UpdateTarget(*target)
	if err != nil {
		ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to update target: %v", err))
		return
	}

	c.Redirect(http.StatusFound, "/admin")
}

func DeleteTarget(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		ReturnError(c, http.StatusBadRequest, "Invalid pubkey ID")
		return
	}
	err = api.DeleteTargetId(id)
	if err != nil {
		ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to delete target: %v", err))
		return
	}
	c.Redirect(http.StatusFound, "/admin")
}

func ChangeUserName(c *gin.Context) {
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
		user.Username = username

		r := regexp.MustCompile("^[a-zA-Z0-9_]{3,20}$")
		if !r.MatchString(username) {
			session.AddFlash("Username must be between 3 and 20 characters and only contain alphanumeric characters and underscore.", "error")
			session.Save()
			c.Redirect(http.StatusFound, "/username")
			return
		}

		// check if username is already taken
		if api.UserExists(username) {
			session.AddFlash("Username is already taken.", "error")
			session.Save()
			c.Redirect(http.StatusFound, "/username")
			return
		}

		if creating {
			err := api.CreateUser(user)
			if err != nil {
				ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to create user: %v", err))
				return
			}
			session.Delete("creatingUser")
		} else {
			err := api.UpdateUser(user)
			if err != nil {
				ReturnError(c, http.StatusBadRequest, fmt.Sprintf("Failed to update user: %v", err))
				return
			}
		}

		user = *api.GetUserByName(user.Username)

		session.Set("user", user)
		session.Save()

		c.Redirect(http.StatusFound, "/account")
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

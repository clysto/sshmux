package main

import (
	"context"
	"net/http"
	"sshmux/sshmux"
	"strconv"

	"github.com/gin-gonic/gin"
)

func Home(c *gin.Context) {
	c.HTML(200, "index", gin.H{})
}

func Login(c *gin.Context) {
	// 生成随机 state 值
	state := RandState()

	// 将 state 存储在 Cookie 中，用于后续验证
	c.SetCookie("oauth_state", state, 3600, "/", c.Request.Host, false, true)

	// 生成授权 URL，并将 state 参数传递给身份提供者
	authCodeURL := ssoConfig.AuthCodeURL(state)

	// 返回 HTML 页面，包含授权 URL
	c.HTML(200, "login", gin.H{
		"authCodeURL": authCodeURL,
		"ssoLabel":    ssoLabel,
	})
}

func Logout(c *gin.Context) {
	c.SetCookie("id_token", "", -1, "/", c.Request.Host, false, true)
	c.Redirect(http.StatusFound, "/")
}

func Account(c *gin.Context) {
	user := c.GetString("user")
	keys := api.GetPubkeysByUser(user)

	c.HTML(200, "account", gin.H{
		"user":    user,
		"pubkeys": keys,
	})
}

func AuthCallback(c *gin.Context) {
	returnedState := c.Query("state")
	code := c.Query("code")

	// 从 Cookie 中获取之前存储的 state
	storedState, err := c.Cookie("oauth_state")
	if err != nil {
		c.String(http.StatusBadRequest, "State cookie not found")
		return
	}

	// 验证 state 是否一致
	if returnedState != storedState {
		c.String(http.StatusBadRequest, "Invalid state parameter")
		return
	}

	token, err := ssoConfig.Exchange(context.Background(), code)
	if err != nil {
		c.String(http.StatusBadRequest, "Failed to exchange token: %v", err)
		return
	}

	// 验证 ID Token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		c.String(http.StatusBadRequest, "No id_token field in oauth2 token")
		return
	}
	c.SetCookie("id_token", rawIDToken, 3600, "/", c.Request.Host, false, true)

	c.Redirect(http.StatusFound, "/account")
}

func CreatePubkey(c *gin.Context) {
	user := c.GetString("user")
	key := c.PostForm("publicKey")

	err := api.CreatePubkey(sshmux.Pubkey{
		User: user,
		Key:  key,
	})
	if err != nil {
		c.String(http.StatusBadRequest, "Failed to create pubkey: %v", err)
		return
	}

	c.Redirect(http.StatusFound, "/account")
}

func DeletePubkey(c *gin.Context) {
	user := c.GetString("user")
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid pubkey ID")
		return
	}
	key := api.GetPubkeyById(id)
	if key == nil || key.User != user {
		c.String(http.StatusBadRequest, "Invalid pubkey ID")
		return
	}
	if key.User != user {
		c.String(http.StatusBadRequest, "Invalid pubkey ID")
		return
	}
	err = api.DeletePubkeyById(id)
	if err != nil {
		c.String(http.StatusBadRequest, "Failed to delete pubkey: %v", err)
		return
	}
	c.Redirect(http.StatusFound, "/account")
}

func Admin(c *gin.Context) {
	targets := api.ListTargets()
	c.HTML(200, "admin", gin.H{
		"targets": targets,
	})
}

func CreateTarget(c *gin.Context) {
	name := c.PostForm("name")
	host := c.PostForm("host")
	port, err := strconv.Atoi(c.PostForm("port"))
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid port")
		return
	}
	user := c.PostForm("user")

	err = api.CreateTarget(sshmux.Target{
		Name: name,
		Host: host,
		Port: int32(port),
		User: user,
	})
	if err != nil {
		c.String(http.StatusBadRequest, "Failed to create target: %v", err)
		return
	}

	c.Redirect(http.StatusFound, "/admin")
}

func UpdateTarget(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid pubkey ID")
		return
	}

	name := c.PostForm("name")
	host := c.PostForm("host")
	port, err := strconv.Atoi(c.PostForm("port"))
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid port")
		return
	}
	user := c.PostForm("user")

	target := api.GetTargetById(id)
	if target == nil {
		c.String(http.StatusBadRequest, "Invalid target ID")
		return
	}
	target.Name = name
	target.Host = host
	target.Port = int32(port)
	target.User = user

	err = api.UpdateTarget(*target)
	if err != nil {
		c.String(http.StatusBadRequest, "Failed to update target: %v", err)
		return
	}

	c.Redirect(http.StatusFound, "/admin")
}

func DeleteTarget(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid pubkey ID")
		return
	}
	err = api.DeleteTargetId(id)
	if err != nil {
		c.String(http.StatusBadRequest, "Failed to delete target: %v", err)
		return
	}
	c.Redirect(http.StatusFound, "/admin")
}

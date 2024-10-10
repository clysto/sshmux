package main

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Auth(admin bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取 cookie 中的 ID Token
		idToken, err := c.Cookie("id_token")
		if err != nil {
			// 如果没有 Token，重定向到登录页面
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// 验证 ID Token
		token, err := ssoVerifier.Verify(context.Background(), idToken)
		if err != nil {
			// 如果 Token 无效，重定向到登录页面
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// 获取用户信息并存储到上下文中
		var claims struct {
			Username       string `json:"preferred_username"`
			ResourceAccess map[string]struct {
				Roles []string `json:"roles"`
			} `json:"resource_access"`
		}
		if err := token.Claims(&claims); err != nil {
			c.String(http.StatusBadRequest, "Failed to parse claims: %v", err)
			c.Abort()
			return
		}

		// 将用户信息存储到上下文
		c.Set("user", claims.Username)
		roles := claims.ResourceAccess[ssoConfig.ClientID]

		// 检查用户是否具有管理员角色
		isAdmin := false
		for _, role := range roles.Roles {
			if role == "admin" {
				isAdmin = true
				break
			}
		}
		c.Set("isAdmin", isAdmin)

		if admin && !isAdmin {
			// 如果需要管理员权限但用户不是管理员，返回 403
			c.String(http.StatusForbidden, "Permission denied")
			c.Abort()
			return
		}

		// 继续请求
		c.Next()
	}
}

package http

import (
	"net/http"
	"sshmux/common"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")
		if user != nil {
			c.Set("user", user.(common.User))
		}
		c.Next()
	}
}

func RequireLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, ok := c.Get("user")
		if !ok {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, ok := c.Get("user")
		if !ok {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		if !user.(common.User).IsAdmin {
			ReturnError(c, http.StatusForbidden, "Forbidden")
			c.Abort()
			return
		}
		c.Next()
	}
}

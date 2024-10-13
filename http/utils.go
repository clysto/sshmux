package http

import (
	"math/rand"
	"net/http"
	"sshmux/common"
	"time"

	"github.com/gin-gonic/gin"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func RandState() string {
	b := make([]byte, 16)
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandBytes(n int) []byte {
	b := make([]byte, n)
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	seededRand.Read(b)
	return b
}

func ReturnError(c *gin.Context, code int, message string) {
	referer := c.Request.Referer()
	if referer == "" {
		referer = "/"
	}
	c.HTML(code, "error", gin.H{
		"code":    code,
		"message": message,
		"referer": referer,
	})
	c.Abort()
}

func ReturnHTML(c *gin.Context, name string, data gin.H) {
	user, ok := c.Get("user")
	theme, err := c.Cookie("theme")
	if err != nil {
		theme = "dark"
	}
	if theme != "dark" && theme != "light" {
		theme = "dark"
	}
	data["theme"] = theme
	if ok {
		data["user"] = user.(common.User)
	}
	data["currentUrl"] = c.Request.URL.Path
	c.HTML(http.StatusOK, name, data)
}

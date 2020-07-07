package crack

import (
	"strconv"
	"sync"

	jwtInterface "github.com/hahwul/jwt-hack/pkg/jwt"
	. "github.com/logrusorgru/aurora"
	log "github.com/sirupsen/logrus"
)

func Crack(mode, token, data string, concurrency, max int, power bool) {
	crackLogger := log.WithFields(log.Fields{
		"common": "this is a common field",
		"other":  "I also should be logged always",
	})
	crackLogger.Info("Start " + mode + " cracking mode")
	if mode == "brute" {
		bf := GenerateBruteforcePayloads(data)
		RunTestingJWT(token, bf, concurrency)
	} else { // if dict
		var words []string
		ff, err := readLinesOrLiteral(data)
		_ = err
		for _, word := range ff {
			words = append(words, word)
		}

		// Remove Deplicated value
		words = unique(words)
		crackLogger.Info("Loaded " + strconv.Itoa(len(words)) + "words (remove duplicated)")
		RunTestingJWT(token, words, concurrency)
	}
}

func RunTestingJWT(token string, lists []string, concurrency int) {
	wordlists := make(chan string)

	// Add go routine job
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for word := range wordlists {
				result, token := jwtInterface.JWTdecodeWithVerify(token, word)
				_ = token
				if result {
					crackLogger.Info("Found! This JWT Token signature secret is " + Green(word))
				}
			}
			wg.Done()
		}()
	}

	// Add data to channel
	for k, v := range lists {
		_ = k
		wordlists <- v
	}

	close(wordlists)
	wg.Wait()
}

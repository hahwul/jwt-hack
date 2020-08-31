package crack

import (
	"fmt"
	"sync"
	"os"

	jwtInterface "github.com/hahwul/jwt-hack/pkg/jwt"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func Crack(mode, token, data string, concurrency, max int, power bool) {
	log.Out = os.Stdout
	fmt.Println("[*] Start " + mode + " cracking mode")
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
		log.WithFields(logrus.Fields{
			"size":   len(words),
		}).Info("Loaded words (remove duplicated)")
		RunTestingJWT(token, words, concurrency)
	}
}

func RunTestingJWT(token string, lists []string, concurrency int) {
	wordlists := make(chan string)
	found := make(chan bool)
	// Add go routine job
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordlists {
				select {
				case <-found:
					break
				default:
					result, token := jwtInterface.JWTdecodeWithVerify(token, word)
					_ = token
					if result {
						log.WithFields(logrus.Fields{
							"Signature":   "Verified",
							"Word":   word,
						}).Info("Found! This JWT Token signature secret is.. ")
						fmt.Println(word)
						found <- true

					} else {
						log.WithFields(logrus.Fields{
							"word":   word,
						}).Info("Invalid signature")
					}
				}
			}
		}()
	}

	// Add data to channel
	for k, v := range lists {
		_ = k
		wordlists <- v
	}

	close(wordlists)
	wg.Wait()
	fmt.Println("[+] Finish crack mode")
}

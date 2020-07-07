package crack

import (
	"fmt"
	"sync"

	jwtInterface "github.com/hahwul/jwt-hack/pkg/jwt"
)

func Crack(mode, token, data string, concurrency, max int, power bool) {
	if mode == "brute" {
		bf := GenerateBruteforcePayloads(data)
		RunTestingJWT(bf, concurrency)
	} else { // if dict
		var words []string
		ff, err := readLinesOrLiteral(data)
		_ = err
		for _, word := range ff {
			words = append(words, word)
		}

		// Remove Deplicated value
		words = unique(words)
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
				fmt.Println(word)
				fmt.Println(jwtInterface.JWTdecodeWithVerify(token, word))
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

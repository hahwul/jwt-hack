package crack

import (
	"fmt"
	"strconv"
	"sync"

	jwtInterface "github.com/hahwul/jwt-hack/pkg/jwt"
	. "github.com/logrusorgru/aurora"
)

func Crack(mode, token, data string, concurrency, max int, power bool) {
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
		fmt.Println("[*] Loaded " + strconv.Itoa(len(words)) + "words (remove duplicated)")
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
					fmt.Println(Green("[+] Signature Verified"))
					fmt.Println(Green("[+] Found! This JWT Token signature secret is ") + Cyan(word))
				} else {
					fmt.Println("[-] Signature Invaild / " + word)
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

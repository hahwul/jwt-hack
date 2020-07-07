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
		fmt.Println("[*] Loaded " + strconv.Itoa(len(words)) + " words (remove duplicated)")
		RunTestingJWT(token, words, concurrency)
	}
}

func RunTestingJWT(token string, lists []string, concurrency int) {
	wordlists := make(chan string)
	found := make(chan bool)
	found <- false
	// Add go routine job
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for word := range wordlists {
				select {
				case <-found:
					wg.Done()
					return
				default:
					result, token := jwtInterface.JWTdecodeWithVerify(token, word)
					_ = token
					if result {
						fmt.Println(Sprintf(Green("[+] Signature Verified / Found! This JWT Token signature secret is %s"), Cyan(word)))
						found <- true

					} else {
						fmt.Println("[-] Signature Invaild / " + word)
					}
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
	fmt.Println("[+] Finish crack mode")
}

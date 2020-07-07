package crack

import (
	"fmt"
	"sync"
)

func Crack(mode, data string, concurrency, power bool) {
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
		RunTestingJWT(words, concurrency)
	}
}

func RunTestingJWT(lists []string, concurrency int) {
	wordlists := make(chan string)

	// Add go routine job
	concurrency = 10
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for word := range wordlists {
				fmt.Println(word)
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

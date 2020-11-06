package crack

import (
	"fmt"
	"sync"
	"os"
	"time"

	jwtInterface "github.com/hahwul/jwt-hack/pkg/jwt"
	"github.com/sirupsen/logrus"
	color "github.com/logrusorgru/aurora"
	"github.com/briandowns/spinner"
)

var log = logrus.New()

func Crack(mode, token, data string, concurrency, max int, power bool, verbose bool) {
	log.Out = os.Stdout
	fmt.Println("[*] Start " + mode + " cracking mode")
	if mode == "brute" {
		bf := GenerateBruteforcePayloads(data)
		RunTestingJWT(token, bf, concurrency, verbose)
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
		RunTestingJWT(token, words, concurrency, verbose)
	}
}

func RunTestingJWT(token string, lists []string, concurrency int, verbose bool) {
	wordlists := make(chan string)
	lenWordlist := len(lists)
	nowLine := 0
	found := false
	secret := ""
	// Add go routine job
	var wg sync.WaitGroup
	s := spinner.New(spinner.CharSets[4], 100*time.Millisecond, spinner.WithWriter(os.Stderr))
	if !verbose {
		percent := float64(nowLine / lenWordlist)
		str := fmt.Sprintf("Cracking.. [%d / %d][%f]",nowLine,lenWordlist,percent)
		s.Suffix = str
		s.Start()
	}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordlists {
				nowLine = nowLine + 1
				percent := (float64(nowLine) / float64(lenWordlist) * 100)
				str := fmt.Sprintf("Cracking.. [%d/%d][%0.2f%%]",nowLine,lenWordlist,percent)
				s.Suffix = str
				if !found {
					result, token := jwtInterface.JWTdecodeWithVerify(token, word)
					_ = token
					if result {
						log.WithFields(logrus.Fields{
							"Signature":   "Verified",
							"Word":   word,
						}).Info("Found! Token signature secret is "+word)
						found = true
						secret = word

					} else {
						if verbose {
							log.WithFields(logrus.Fields{
								"word":   word,
							}).Info("Invalid signature")
						}
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
	
	if !verbose {
		s.Stop()
	}
	if found {
		fmt.Println("[+] Found! JWT signature secret:",color.BrightYellow(secret))
	}
	fmt.Println("[+] Finish crack mode")
}

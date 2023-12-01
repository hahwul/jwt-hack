package crack

func GenerateBruteforcePayloads(chars string, max int) []string {
	var payloads []string
	for str := range generate(chars, max) {
		payloads = append(payloads, str)
	}
	return payloads
}

func generate(alphabet string, max int) <-chan string {
	c := make(chan string)

	go func() {
		defer close(c)
		if max <= 0 {
			return
		}
		word := make(Word, max)
		for i := 1; i <= max; i++ {
			generateRecursive(c, alphabet, i, word, 0)
		}
	}()

	return c
}

type Word []rune

func (w Word) Permute(out chan<- string, max int) {
	if len(w) <= max {
		out <- string(w)
		return
	}

	// Write first result manually.
	out <- string(w)

	for w.next() {
		if len(w) <= max {
			out <- string(w)
		}
	}
}

//Generating strings recursively
func generateRecursive(out chan<- string, alphabet string, max int, current Word, index int) {
	if index == max {
		out <- string(current)
		return
	}

	for _, char := range alphabet {
		current[index] = char
		generateRecursive(out, alphabet, max, current, index+1)
	}
}

// next performs a single permutation by shuffling characters around.
// Returns false if there are no more new permutations.
func (w Word) next() bool {
	var left, right int

	left = len(w) - 2
	for w[left] >= w[left+1] && left >= 1 {
		left--
	}

	if left == 0 && w[left] >= w[left+1] {
		return false
	}

	right = len(w) - 1
	for w[left] >= w[right] {
		right--
	}

	w[left], w[right] = w[right], w[left]

	left++
	right = len(w) - 1

	for left < right {
		w[left], w[right] = w[right], w[left]
		left++
		right--
	}

	return true
}

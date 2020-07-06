package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var wordlist, chars, mode string
var lmin, lmax, conc int

// crackCmd represents the crack command
var crackCmd = &cobra.Command{
	Use:   "crack",
	Short: "Cracking JWT Token",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("crack called")
	},
}

func init() {
	rootCmd.AddCommand(crackCmd)

	crackCmd.PersistentFlags().StringVarP(&mode, "mode", "m", "dict", "cracking mode, you can use 'dict' or 'brute'")
	crackCmd.PersistentFlags().StringVarP(&wordlist, "wordlist", "w", "", "wordlist file / only dictionary attack")
	crackCmd.PersistentFlags().StringVar(&chars, "chars", "abcdefghijklmnopqrstuvwxyz0123456789", "char list / only bruteforce")
	crackCmd.PersistentFlags().IntVar(&lmin, "lmin", 1, "length of min / only bruteforce")
	crackCmd.PersistentFlags().IntVar(&lmax, "lmax", 8, "length of max / only bruteforce")

	crackCmd.PersistentFlags().IntVarP(&conc, "concurrency", "c", 100, "number of concurrency")
	crackCmd.Flags().BoolP("power", "t", false, "Used all CPU your computer")

	// crackCmd.PersistentFlags().StringVar(&foo,"foo", "", "A help for foo")
}

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

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

	// crackCmd.PersistentFlags().String("foo", "", "A help for foo")
	// crackCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

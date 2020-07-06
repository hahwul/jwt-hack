package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// payloadCmd represents the payload command
var payloadCmd = &cobra.Command{
	Use:   "payload",
	Short: "Generate JWT Attack payloads",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("payload called")
	},
}

func init() {
	rootCmd.AddCommand(payloadCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// payloadCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// payloadCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

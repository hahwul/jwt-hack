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

	// payloadCmd.PersistentFlags().String("foo", "", "A help for foo")
	// payloadCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

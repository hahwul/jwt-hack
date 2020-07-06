package cmd

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
	jwtInterface "github.com/hahwul/jwt-hack/pkg/jwt"
	"github.com/spf13/cobra"
)

// payloadCmd represents the payload command
var payloadCmd = &cobra.Command{
	Use:   "payload",
	Short: "Generate JWT Attack payloads",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("payload called")
		var token *jwt.Token
		token = jwtInterface.JWTDecode(args[0])
		jwtInterface.generateAllPayloads(token)
	},
}

func init() {
	rootCmd.AddCommand(payloadCmd)

	// payloadCmd.PersistentFlags().String("foo", "", "A help for foo")
	// payloadCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

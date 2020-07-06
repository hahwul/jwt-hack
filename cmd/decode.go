package cmd

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
	jwtInterface "github.com/hahwul/jwt-hack/pkg/jwt"
	"github.com/spf13/cobra"
)

// decodeCmd represents the decode command
var decodeCmd = &cobra.Command{
	Use:   "decode [JWT Token]",
	Short: "Decode JWT to JSON",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) >= 1 {
			var token *jwt.Token
			token = jwtInterface.JWTdecode(args[0])
			fmt.Println(token.Raw)
			fmt.Println(token.Method)
			fmt.Println(token.Header)
			fmt.Println(token.Claims)
		} else {

		}
	},
}

func init() {
	rootCmd.AddCommand(decodeCmd)

	// decodeCmd.PersistentFlags().String("foo", "", "A help for foo")
}

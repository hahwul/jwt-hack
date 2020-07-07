package cmd

import (
	"fmt"
	"os"

	"github.com/dgrijalva/jwt-go"
	jwtInterface "github.com/hahwul/jwt-hack/pkg/jwt"

	//. "github.com/logrusorgru/aurora"
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
			fmt.Fprintln(os.Stderr, "[ Raw data ]")
			fmt.Println(token.Raw)
			fmt.Fprintln(os.Stderr, "[ Method ]")
			fmt.Println(token.Method)
			fmt.Fprintln(os.Stderr, "[ Headers ]")
			fmt.Println(token.Header)
			fmt.Fprintln(os.Stderr, "[ Claims ]")
			fmt.Println(token.Claims)
		} else {

		}
	},
}

func init() {
	rootCmd.AddCommand(decodeCmd)

	// decodeCmd.PersistentFlags().String("foo", "", "A help for foo")
}

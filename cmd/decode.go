package cmd

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
	jwtInterface "github.com/hahwul/jwt-hack/pkg/jwt"
	"github.com/spf13/cobra"
)

// decodeCmd represents the decode command
var decodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "Decode JWT to JSON",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) >= 1 {
			var token *jwt.Token
			fmt.Println(args[0])
			token = jwtInterface.JWTdecode(args[0])
			fmt.Println(token)
		} else {

		}
	},
}

func init() {
	rootCmd.AddCommand(decodeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// decodeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// decodeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

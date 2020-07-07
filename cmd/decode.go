package cmd

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
	jwtInterface "github.com/hahwul/jwt-hack/pkg/jwt"

	//. "github.com/logrusorgru/aurora"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// decodeCmd represents the decode command
var decodeCmd = &cobra.Command{
	Use:   "decode [JWT Token]",
	Short: "Decode JWT to JSON",
	Run: func(cmd *cobra.Command, args []string) {
		contextLogger := log.WithFields(log.Fields{
			"common": "this is a common field",
		})
		if len(args) >= 1 {
			var token *jwt.Token
			token = jwtInterface.JWTdecode(args[0])
			contextLogger.Info("RawData")
			fmt.Println(token.Raw)
			contextLogger.Info("Method")
			fmt.Println(token.Method)
			contextLogger.Info("Headers")
			fmt.Println(token.Header)
			contextLogger.Info("Claims")
			fmt.Println(token.Claims)
		} else {

		}
	},
}

func init() {
	rootCmd.AddCommand(decodeCmd)

	// decodeCmd.PersistentFlags().String("foo", "", "A help for foo")
}

package cmd

import (
	"fmt"
	"os"
	"encoding/json"

	"github.com/dgrijalva/jwt-go"
	jwtInterface "github.com/hahwul/jwt-hack/pkg/jwt"

	//. "github.com/logrusorgru/aurora"
	"github.com/spf13/cobra"
	"github.com/sirupsen/logrus"
)

// decodeCmd represents the decode command
var decodeCmd = &cobra.Command{
	Use:   "decode [JWT Token]",
	Short: "Decode JWT to JSON",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) >= 1 {
			var token *jwt.Token
			var log = logrus.New()
			log.Out = os.Stdout
			token = jwtInterface.JWTdecode(args[0])
			header,_ := json.Marshal(token.Header)
			log.WithFields(logrus.Fields{
				"method": token.Method,
				"header": string(header),
			}).Info("Decoded data(claims)")
			data,_ := json.Marshal(token.Claims)
			fmt.Println(string(data))
		} else {
			var log = logrus.New()
			log.Out = os.Stdout
			log.Error("Arguments Error")
		}
	},
}

func init() {
	rootCmd.AddCommand(decodeCmd)

	// decodeCmd.PersistentFlags().String("foo", "", "A help for foo")
}

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	jwtInterface "github.com/hahwul/jwt-hack/pkg/jwt"

	//. "github.com/logrusorgru/aurora"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// decodeCmd represents the decode command
var decodeCmd = &cobra.Command{
	Use:   "decode [JWT Token]",
	Short: "Decode JWT to JSON",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) >= 1 {
			var token *jwt.Token
			var log = logrus.New()
			var jdata map[string]interface{}

			log.Out = os.Stdout
			token = jwtInterface.JWTdecode(args[0])
			if token == nil {
				log.Error("JWT Decode Error")
				os.Exit(1)
			}
			header, err := json.Marshal(token.Header)
			if err != nil {
				log.Error("JSON Marshal Error")
				os.Exit(1)
			}
			log.WithFields(logrus.Fields{
				"method": token.Method,
				"header": string(header),
			}).Info("Decoded data(claims)")

			data, _ := json.Marshal(token.Claims)
			json.Unmarshal([]byte(data), &jdata)

			if jdata["iat"] != nil {
				iatf := jdata["iat"].(float64)
				iats := fmt.Sprintf("%.0f", iatf)
				iat, _ := strconv.Atoi(iats)
				iatt := time.Unix(0, int64(iat))
				log.WithFields(logrus.Fields{
					"IAT":  iats,
					"TIME": iatt,
				}).Info("Issued At Time")
			}
			if jdata["exp"] != nil {
				expf := jdata["exp"].(float64)
				exps := fmt.Sprintf("%.0f", expf)
				exp, _ := strconv.Atoi(exps)
				expt := time.Unix(0, int64(exp))
				log.WithFields(logrus.Fields{
					"EXP":  exps,
					"TIME": expt,
				}).Info("Expiraton Time")
			}
			fmt.Println(string(data))
		} else {
			var log = logrus.New()
			log.Out = os.Stdout
			log.Error("Arguments Error")
			log.Error("e.g jwt-hack decode {JWT_CODE}")
		}
	},
}

func init() {
	rootCmd.AddCommand(decodeCmd)

	// decodeCmd.PersistentFlags().String("foo", "", "A help for foo")
}

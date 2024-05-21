package cmd

import (
	"os"

	"github.com/golang-jwt/jwt/v5"
	jwtInterface "github.com/hahwul/jwt-hack/pkg/jwt"
	jwtPayload "github.com/hahwul/jwt-hack/pkg/payload"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var turl, aurl, protocol string

// payloadCmd represents the payload command
var payloadCmd = &cobra.Command{
	Use:   "payload [JWT Token]",
	Short: "Generate JWT Attack payloads",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) >= 1 {
			var token *jwt.Token
			token = jwtInterface.JWTdecode(args[0])
			if token == nil {
				log.Error("JWT Decode Error")
				os.Exit(1)
			}
			jwtPayload.GenerateAllPayloads(token, turl, aurl, protocol)
		} else {
			log.Error("Arguments Error")
			log.Error("e.g jwt-hack payload {JWT_CODE}")
		}
	},
}

func init() {
	rootCmd.AddCommand(payloadCmd)

	payloadCmd.PersistentFlags().StringVar(&turl, "jwk-trust", "", "A trusted domain for jku&x5u (e.g google.com)")
	payloadCmd.PersistentFlags().StringVar(&aurl, "jwk-attack", "", "A attack payload domain for jku&x5u (e.g hahwul.com)")
	payloadCmd.PersistentFlags().StringVar(&protocol, "jwk-protocol", "https", "jku&x5u protocol (http/https)")
	// payloadCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

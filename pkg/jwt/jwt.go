package jwtInterface

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

// JWTencode is JWT interface for encode
func JWTencode(claims map[string]interface{}, secret, alg string) string {
	var key = []byte(secret)
	var jwtClaims = jwt.MapClaims(claims)

	algorithm := jwt.GetSigningMethod(alg)

	token := jwt.NewWithClaims(algorithm, jwtClaims)
	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(key)
	_ = err
	return tokenString
}

// JWTdecode is JWT interface for decode
func JWTdecode(tokenString string) *jwt.Token {
	// signature := false

	// Parse the token
	var token *jwt.Token
	var err error
	parser := new(jwt.Parser)
	// Figure out correct claims type
	token, _, err = parser.ParseUnverified(tokenString, jwt.MapClaims{})
	//token, _, err = parser.ParseUnverified(tokenString, &jwt.StandardClaims{})

	if err != nil {
		fmt.Errorf("[%v] Invalid token", err)
		return nil
	}
	return token
}

// JWTdecodeWithVerify is interface for decode with verify
func JWTdecodeWithVerify(tokenString, secret string) (bool, *jwt.Token) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return false, nil
		}
		return []byte(secret), nil
	})
	if err != nil {
		return false, nil
	}
	return true, token
}

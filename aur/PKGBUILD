# Maintainer: HAHWUL <hahwul@gmail.com>
pkgname=jwt-hack
pkgver=2.6.0
pkgrel=1
pkgdesc="Hack the JWT (JSON Web Token) - JWT security testing and token manipulation"
arch=('x86_64' 'aarch64')
url="https://github.com/hahwul/jwt-hack"
license=('MIT')
depends=('gcc-libs')
makedepends=('cargo')
# Disable LTO: makepkg's -flto leaks into the `cc` builds of jwt-hack's C
# dependencies (aws-lc-sys, ring, vendored openssl), producing objects that
# fail to link with lld (undefined symbols). Cargo's own `lto = true` for the
# Rust crate graph is unaffected.
options=(!lto)
source=("$pkgname-$pkgver.tar.gz::https://github.com/hahwul/jwt-hack/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')

prepare() {
    cd "$pkgname-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    cargo fetch --locked --target "$(rustc -vV | sed -n 's/host: //p')"
}

build() {
    cd "$pkgname-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    export CARGO_TARGET_DIR=target
    cargo build --frozen --release
}

check() {
    cd "$pkgname-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    cargo test --frozen --release
}

package() {
    cd "$pkgname-$pkgver"
    install -Dm0755 -t "$pkgdir/usr/bin/" "target/release/$pkgname"
    install -Dm0644 -t "$pkgdir/usr/share/licenses/$pkgname/" LICENSE
    install -Dm0644 -t "$pkgdir/usr/share/doc/$pkgname/" README.md
}

#!/bin/bash
SHELL=/bin/bash
VERSION=$(grep "version" Cargo.toml | head -n 1 | grep -Eo "[0-9].[0-9].[0-9]")
LICENSE="MIT"
MAINTAINER="Mike Lubinets <lubinetsm@yandex.ru>"
DESCRIPTION="Fast asynchronous DNS resolver"
URL="https://github.com/mersinvald/batch_resolve"

# Build statuc binary
~/.bin/rust-musl-builder cargo build --release || exit 1

# Make temp release dir
mkdir -p packaging/temp

# Copy release into temp folder
cp target/x86_64-unknown-linux-musl/release/batch_resolve packaging/temp

cd packaging

fpm -s dir -t deb --version "$VERSION" --description "$DESCRIPTION" --url "$URL" --name "batch_resolve" --maintainer "$MAINTAINER" temp/batch_resolve=/usr/bin/batch_resolve ../batch_resolve.toml=/etc/batch_resolve.toml
fpm -s dir -t rpm --version "$VERSION" --description "$DESCRIPTION" --url "$URL" --name "batch_resolve" --maintainer "$MAINTAINER" temp/batch_resolve=/usr/bin/batch_resolve ../batch_resolve.toml=/etc/batch_resolve.toml

rm -rf temp/

# Update aur package
git clone ssh://aur@aur.archlinux.org/batch_resolve.git || exit 1
cd batch_resolve
pwd
sed -i "s/pkgver=.*/pkgver=$VERSION/g" PKGBUILD

HASH=$(makepkg -g)
sed -i "/md5sums=.*/d" PKGBUILD
echo $HASH >> PKGBUILD

makepkg --printsrcinfo > .SRCINFO

cat PKGBUILD

git add PKGBUILD .SRCINFO && git commit -m "Version $VERSION" && git push

cd ..
rm -rf batch_resolve/
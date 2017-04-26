#!/bin/bash
SHELL=/bin/bash
VERSION=$(grep "version" Cargo.toml | head -n 1 | grep -Eo "[0-9].[0-9].[0-9]")
LICENSE="MIT"
MAINTAINER="Mike Lubinets <lubinetsm@yandex.ru>"
DESCRIPTION="Fast asynchronous DNS resolver"
URL="https://github.com/mersinvald/batch_resolve"

# Build statuc binary
~/.bin/rust-musl-builder cargo build --release

# Make temp release dir
mkdir -p packaging/temp

# Copy release into temp folder
cp target/x86_64-unknown-linux-musl/release/batch_resolve packaging/temp

cd packaging

fpm -s dir -t deb --version "$VERSION" --description "$DESCRIPTION" --url "$URL" --name "batch_resolve" --maintainer "$MAINTAINER" temp/batch_resolve=/usr/bin/batch_resolve
fpm -s dir -t rpm --version "$VERSION" --description "$DESCRIPTION" --url "$URL" --name "batch_resolve" --maintainer "$MAINTAINER" temp/batch_resolve=/usr/bin/batch_resolve
fpm -s dir -t pacman --version "$VERSION" --description "$DESCRIPTION" --url "$URL" --name "batch_resolve" --maintainer "$MAINTAINER" temp/batch_resolve=/usr/bin/batch_resolve

rm -rf temp/

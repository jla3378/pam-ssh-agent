#!/bin/sh
set -ex
VERSION=0.9.6
RUST_VERSION=1.89
PATH=/usr/lib/rust-${RUST_VERSION}/bin:/usr/bin

rm -rf vendor
cargo vendor-filterer --platform "*-unknown-linux-gnu"
tar cfJ ../pam-ssh-agent_${VERSION}.orig-vendor.tar.xz vendor

tar cfJ ../pam-ssh-agent_${VERSION}.orig.tar.xz src examples tests \
 .github LICENSE* README* create-deb-dsc.sh rust-toolchain.toml Cargo*

debuild -S -sa

#!/bin/sh

cabal v2-update
cabal v2-build --enable-documentation --enable-tests
cabal v2-test --enable-tests || exit 1
cabal v2-install --lib

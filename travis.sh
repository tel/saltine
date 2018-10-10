#!/bin/sh

function version_gte() {
    test "$(printf '%s\n' "$@" | sort -V -r | head -n 1)" == "$1";
}

rm -rf .cabal-sandbox
cabal update

if version_gte $CABALVER "2.0"; then
    cabal new-build --enable-documentation --enable-tests
    cabal new-test
    cabal sdist && cabal install --force-reinstalls dist/saltine-*.tar.gz
else
    cabal sandbox init
    cabal install --only-dependencies --enable-tests -j4
    cabal build
    cabal haddock
    cabal test --show-details=always
    cabal check
    cabal sdist && cabal install --force-reinstalls dist/saltine-*.tar.gz
fi

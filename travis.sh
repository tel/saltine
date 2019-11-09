#!/bin/sh

version_gte() {
    test "$(printf '%s\n' "$@" | sort -V -r | head -n 1)" = "$1";
}

rm -rf .cabal-sandbox
cabal update

if version_gte "$CABALVER" "2.0"; then
    cabal v2-build --enable-documentation --enable-tests
    cabal v2-test --enable-tests || exit 1
    cabal v2-sdist && cabal v2-install --force-reinstalls dist-newstyle/sdist/saltine-*.tar.gz
else
    cabal v1-sandbox init
    cabal v1-install --only-dependencies --enable-tests -j4
    cabal v1-build
    cabal v1-haddock
    cabal v1-test --show-details=always || exit 1
    cabal v1-check
    cabal v1-sdist && cabal v1-install --force-reinstalls dist/saltine-*.tar.gz
fi

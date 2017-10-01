#!/bin/sh

rm -rf .cabal-sandbox
cabal update
cabal sandbox init

if [ "$CABALVER" != "2.0" ]; then
    cabal install --only-dependencies --enable-tests -j4
    cabal build
    cabal haddock
    cabal test --show-details=always
    cabal check
    cabal sdist && cabal install --force-reinstalls dist/saltine-*.tar.gz
else
    cabal new-build --enable-documentation --enable-tests
    cabal new-test
    cabal sdist && cabal install --force-reinstalls dist/saltine-*.tar.gz
fi

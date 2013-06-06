
deps:
	cabal install --only-dependencies --enable-test -j4

configure: deps
	cabal configure --enable-test

build: configure
	cabal build

test: build
	cabal test

clean:
	cabal clean

all: test


.PHONY: deps configure build test all

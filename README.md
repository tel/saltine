# Saltine

A Haskell binding for @jedisct1's portable binding for djb's NaCl.

``` haskell
-- not implemented yet

import Crypto.Saltine

main = do
  k <- newKey
  n <- newNonce
  let ciphertext = encrypt k n "Hello world"
  print $ decrypt k n ciphertext

-- Just "Hello world"

```

In
[*The Security Impact of a New Cryptographic Library*](http://cryptojedi.org/papers/coolnacl-20111201.pdf)
Bernstein, Lange, and Schwabe argue that high-level cryptographic
libraries are important for eliminating spaces of cryptographic
disasters caused by improper implementation and combination of
cryptographic primitives. In short, they claim cryptosystems often
fail disasterously because of errors such as improper primitive
configuration.

[NaCl](http://nacl.cr.yp.to/) is Bernstein, Lange, and Schwabe's
solution: a high-level, performant cryptography library with a no-fuss
interface. [Saltine](http://github.com/tel/saltine) is a Haskell
binding to NaCl (via
[`libsodium`](https://github.com/jedisct1/libsodium)) which hopes to
provide even more simplicity and safty to the usage of cryptography.

Tested with `libsodium-4.1`.

[![Build Status](https://travis-ci.org/tel/saltine.png?branch=master)](https://travis-ci.org/tel/saltine)

Inspired by @thoughtpolice's
[`salt`](http://github.com/thoughtpolice/salt) library. `salt` also
binds to NaCl, but uses a Haskell managed version of djb's code
instead of `libsodium`.

# Todos

* Tests for Hash
* Tests for ScalarMult
* Typesafety for `ScalarMult` (How?)
* Extract unit tests from "[Cryptography in NaCl](http://cr.yp.to/highspeed/naclcrypto-20090310.pdf)"

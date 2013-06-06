# Saltine 0.0.0.1

A Haskell binding for @jedisct1's portable binding for djb's
NaCl. **This is an early release.** Please try it out, but don't just
yet stake your life or job on it.

``` haskell
import Crypto.Saltine
import qualified Data.Vector.Storable as V

main = do
  k <- newKey
  n <- newNonce
  let ciphertext = secretbox k n (V.fromList [1,2,3,4,5])
  print $ secreboxOpen k n ciphertext

-- Just (fromList [1,2,3,4,5])
```

In
[*The Security Impact of a New Cryptographic Library*](http://cryptojedi.org/papers/coolnacl-20111201.pdf)
Bernstein, Lange, and Schwabe argue that high-level cryptographic
libraries eliminate whole spaces of cryptographic disasters which are
nigh inevitable whenever programmers use low-level crypto primitives.

* [Security Stack Exchange: Why Shouldn't We Roll Our Own?](http://security.stackexchange.com/questions/18197/why-shouldnt-we-roll-our-own)
* [Hacker News on "All the Crypto Code You've Ever Written is Probably Broken"](https://news.ycombinator.com/item?id=4779015)
* [Stack Overflow: When can you trust yourself to implement cryptography based solutions?](http://stackoverflow.com/questions/1914257/when-can-you-trust-yourself-to-implement-cryptography-based-solutions)
* [Coding Horror: Why isn't my encryption... encrypting?](http://www.codinghorror.com/blog/2009/05/why-isnt-my-encryption-encrypting.html)

Crypto is complicated, so pre-rolled solutions are important
prevention mechanisms.

[NaCl](http://nacl.cr.yp.to/) is Bernstein, Lange, and Schwabe's
solution: a high-level, performant cryptography library with a no-fuss
interface. [Saltine](http://github.com/tel/saltine) is a Haskell
binding to NaCl (via
[`libsodium`](https://github.com/jedisct1/libsodium)) which hopes to
provide even more simplicity and safety to the usage of cryptography.

Note that it's still possible to shoot yourself in the foot pretty
easily using Saltine. Nonces must always be unique. 
`Crypto.Saltine.Core.Stream` produces messages which can be 
undetectably tampered with in-flight. Keys are insecurely read from 
disk—they may be copied and then paged back to disk. Use Saltine carefully.


Tested with `libsodium-4.1`.

[![Build Status](https://travis-ci.org/tel/saltine.png?branch=master)](https://travis-ci.org/tel/saltine)

Inspired by @thoughtpolice's
[`salt`](http://github.com/thoughtpolice/salt) library. `salt` also
binds to NaCl, but uses a Haskell managed version of djb's code
instead of `libsodium`.

# Todos

* Tests for Hash
* Tests for ScalarMult
* Nonce tests
* Encode/Decode tests
* Extract unit tests from "[Cryptography in NaCl](http://cr.yp.to/highspeed/naclcrypto-20090310.pdf)"
* Consider thread safety for random generation functions,
  `randombytes_random`, `randombytes_uniform`, `randombytes_buf`,
  `randombytes_close`, `crypto_sign_keypair`, and
  `crypto_box_keypair`.
* Benchmarks (does `-O2` or `-funbox-strict-fields` help?)

# Backlog

* `Message` type for easy `Vector` encoding (see
  [`message`](https://github.com/tel/saltine/tree/message) branch)
* Ideas for how to isolate key generation `IO` from general use, noncing strategies
* How in the world should `ScalarMult` be packaged?
  * Built-in hashed DH exchange? Based on `pipes`?
* Benchmarking
* "Lens of Saltine"

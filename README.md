# Saltine 0.2.0.0 [![Hackage version](https://img.shields.io/hackage/v/saltine.svg?colorB=4FB900)](https://hackage.haskell.org/package/saltine)

A Haskell binding for @jedisct1's portable binding for djb's
NaCl. **This is an early release.** Please try it out, but don't just
yet stake your life or job on it.

It is imperative you call `sodiumInit` before using any other function.

``` haskell
import           Crypto.Saltine
import           Crypto.Saltine.Core.SecretBox
import qualified Data.ByteString.Char8 as BSC8

main = do
  sodiumInit
  k <- newKey
  n <- newNonce
  let ciphertext = secretbox k n (BSC8.pack "foobar")
  print $ secretboxOpen k n ciphertext

-- Just "foobar"
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
easily using Saltine. Nonces must always be unique which must be managed 
by the library user.
[`Crypto.Saltine.Core.Stream`](https://github.com/tel/saltine/blob/master/src/Crypto/Saltine/Core/Stream.hs)
produces messages which can beundetectably tampered with in-flight. 
Keys are insecurely read from disk—they may be copied and then paged 
back to disk.

When uncertain, use [`Crypto.Saltine.Core.SecretBox`](https://github.com/tel/saltine/blob/master/src/Crypto/Saltine/Core/SecretBox.hs) 
and [`Crypto.Saltine.Core.Box`](https://github.com/tel/saltine/blob/master/src/Crypto/Saltine/Core/Box.hs).
If you can think of ways to use Haskell's type system to enforce 
security invariants, please suggest them.

To use it on Windows systems, download 
[a prebuild libsodium-\*-stable-mingw.tar.gz file](https://download.libsodium.org/libsodium/releases/) 
and copy the files in `libsodium-win64`  into the equivalent places 
in `C:\Program Files\Haskell Platform\*\mingw`. Then just add saltine 
to your cabal file and watch it go.

Tested with [`libsodium-1.0.18`](https://download.libsodium.org/libsodium/releases/).

Inspired by @thoughtpolice's
[`salt`](http://github.com/thoughtpolice/salt) library. `salt` also
binds to NaCl, but uses a Haskell managed version of djb's code
instead of `libsodium`.

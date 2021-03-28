-- |
-- Module      : Crypto.Saltine.Core.SecretBox
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
-- Secret-key authenticated encryption:
-- "Crypto.Saltine.Core.SecretBox"
--
-- The 'secretbox' function encrypts and authenticates a message
-- 'ByteString' using a secret key and a nonce. The 'secretboxOpen'
-- function verifies and decrypts a ciphertext 'ByteString' using a
-- secret key and a nonce. If the ciphertext fails validation,
-- 'secretboxOpen' returns 'Nothing'.
--
-- The "Crypto.Saltine.Core.SecretBox" module is designed to meet
-- the standard notions of privacy and authenticity for a secret-key
-- authenticated-encryption scheme using nonces. For formal
-- definitions see, e.g., Bellare and Namprempre, "Authenticated
-- encryption: relations among notions and analysis of the generic
-- composition paradigm," Lecture Notes in Computer Science 1976
-- (2000), 531–545, <http://www-cse.ucsd.edu/~mihir/papers/oem.html>.
--
-- Note that the length is not hidden. Note also that it is the
-- caller's responsibility to ensure the uniqueness of nonces—for
-- example, by using nonce 1 for the first message, nonce 2 for the
-- second message, etc. Nonces are long enough that randomly generated
-- nonces have negligible risk of collision.
--
-- "Crypto.Saltine.Core.SecretBox" is
-- @crypto_secretbox_xsalsa20poly1305@, a particular combination of
-- Salsa20 and Poly1305 specified in \"Cryptography in NaCl\"
-- (<http://nacl.cr.yp.to/valid.html>). This function is conjectured
-- to meet the standard notions of privacy and authenticity.
--
-- This is version 2010.08.30 of the secretbox.html web page.
module Crypto.Saltine.Core.SecretBox (
  Key, Nonce, Authenticator,
  secretbox, secretboxOpen,
  secretboxDetached, secretboxOpenDetached,
  newKey, newNonce
  ) where

import Crypto.Saltine.Internal.SecretBox
            ( c_secretbox
            , c_secretbox_detached
            , c_secretbox_open
            , c_secretbox_open_detached
            , Key(..)
            , Nonce(..)
            , Authenticator(..)
            )
import Crypto.Saltine.Internal.Util as U
import Data.ByteString              (ByteString)

import qualified Crypto.Saltine.Internal.SecretBox as Bytes
import qualified Data.ByteString                   as S

-- | Creates a random key of the correct size for 'secretbox'.
newKey :: IO Key
newKey = Key <$> randomByteString Bytes.secretbox_keybytes

-- | Creates a random nonce of the correct size for 'secretbox'.
newNonce :: IO Nonce
newNonce = Nonce <$> randomByteString Bytes.secretbox_noncebytes

-- | Encrypts a message. It is infeasible for an attacker to decrypt
-- the message so long as the 'Nonce' is never repeated.
secretbox
    :: Key
    -> Nonce
    -> ByteString
    -- ^ Message
    -> ByteString
    -- ^ Ciphertext
secretbox (Key key) (Nonce nonce) msg =
  unpad' . snd . buildUnsafeByteString len $ \pc ->
    constByteStrings [key, pad' msg, nonce] $ \
      [(pk, _), (pm, _), (pn, _)] ->
        c_secretbox pc pm (fromIntegral len) pn pk
  where len    = S.length msg + Bytes.secretbox_zerobytes
        pad'   = pad Bytes.secretbox_zerobytes
        unpad' = unpad Bytes.secretbox_boxzerobytes

-- | Encrypts a message. In contrast with 'secretbox', the result is not
-- serialized as one element and instead provided as an authentication tag and
-- ciphertext.
secretboxDetached
    :: Key
    -> Nonce
    -> ByteString
    -- ^ Message
    -> (Authenticator,ByteString)
    -- ^ (Authentication Tag, Ciphertext)
secretboxDetached (Key key) (Nonce nonce) msg =
  buildUnsafeByteString ctLen $ \pc ->
    fmap (Au . snd) . buildUnsafeByteString' tagLen $ \ptag ->
      constByteStrings [key, msg, nonce] $ \
        [(pk, _), (pmsg, _), (pn, _)] ->
          c_secretbox_detached pc ptag pmsg (fromIntegral ptLen) pn pk
  where ctLen  = ptLen
        ptLen  = S.length msg
        tagLen = Bytes.secretbox_macbytes

-- | Decrypts a message. Returns 'Nothing' if the keys and message do
-- not match.
secretboxOpen
    :: Key
    -> Nonce
    -> ByteString
    -- ^ Ciphertext
    -> Maybe ByteString
    -- ^ Message
secretboxOpen (Key key) (Nonce nonce) cipher =
  let (err, vec) = buildUnsafeByteString len $ \pm ->
        constByteStrings [key, pad' cipher, nonce] $ \
          [(pk, _), (pc, _), (pn, _)] ->
            c_secretbox_open pm pc (fromIntegral len) pn pk
  in hush . handleErrno err $ unpad' vec
  where len    = S.length cipher + Bytes.secretbox_boxzerobytes
        pad'   = pad Bytes.secretbox_boxzerobytes
        unpad' = unpad Bytes.secretbox_zerobytes

-- | Decrypts a message. Returns 'Nothing' if the keys and message do
-- not match.
secretboxOpenDetached
    :: Key
    -> Nonce
    -> Authenticator
    -- ^ Auth Tag
    -> ByteString
    -- ^ Ciphertext
    -> Maybe ByteString
    -- ^ Message
secretboxOpenDetached (Key key) (Nonce nonce) (Au tag) cipher
    | S.length tag /= Bytes.secretbox_macbytes = Nothing
    | otherwise =
  let (err, vec) = buildUnsafeByteString len $ \pm ->
        constByteStrings [key, cipher, tag, nonce] $ \
          [(pk, _), (pc, _), (pt, _), (pn, _)] ->
            c_secretbox_open_detached pm pc pt (fromIntegral len) pn pk
  in hush . handleErrno err $ vec
  where len    = S.length cipher

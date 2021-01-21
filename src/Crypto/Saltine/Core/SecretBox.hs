{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, DeriveGeneric #-}

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
  Key, Nonce,
  secretbox, secretboxOpen,
  secretboxDetached, secretboxOpenDetached,
  newKey, newNonce
  ) where

import           Crypto.Saltine.Class
import           Crypto.Saltine.Internal.Util      as U
import qualified Crypto.Saltine.Internal.SecretBox as Bytes

import           Control.Applicative
import           Foreign.C
import           Foreign.Ptr
import qualified Data.ByteString                   as S
import           Data.ByteString                     (ByteString)
import           Data.Hashable (Hashable)
import           Data.Data (Data, Typeable)
import           GHC.Generics (Generic)

-- $types

-- | An opaque 'secretbox' cryptographic key.
newtype Key = Key ByteString deriving (Ord, Hashable, Data, Typeable, Generic)
instance Eq Key where
    Key a == Key b = U.compare a b

instance IsEncoding Key where
  decode v = if S.length v == Bytes.secretBoxKey
           then Just (Key v)
           else Nothing
  {-# INLINE decode #-}
  encode (Key v) = v
  {-# INLINE encode #-}

-- | An opaque 'secretbox' nonce.
newtype Nonce = Nonce ByteString deriving (Eq, Ord, Hashable, Data, Typeable, Generic)

instance IsEncoding Nonce where
  decode v = if S.length v == Bytes.secretBoxNonce
           then Just (Nonce v)
           else Nothing
  {-# INLINE decode #-}
  encode (Nonce v) = v
  {-# INLINE encode #-}

instance IsNonce Nonce where
  zero            = Nonce (S.replicate Bytes.secretBoxNonce 0)
  nudge (Nonce n) = Nonce (nudgeBS n)

-- | Creates a random key of the correct size for 'secretbox'.
newKey :: IO Key
newKey = Key <$> randomByteString Bytes.secretBoxKey

-- | Creates a random nonce of the correct size for 'secretbox'.
newNonce :: IO Nonce
newNonce = Nonce <$> randomByteString Bytes.secretBoxNonce

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
  where len    = S.length msg + Bytes.secretBoxZero
        pad'   = pad Bytes.secretBoxZero
        unpad' = unpad Bytes.secretBoxBoxZero

-- | Encrypts a message. In contrast with 'secretbox', the result is not
-- serialized as one element and instead provided as an authentication tag and
-- ciphertext.
secretboxDetached
    :: Key
    -> Nonce
    -> ByteString
    -- ^ Message
    -> (ByteString,ByteString)
    -- ^ (Authentication Tag, Ciphertext)
secretboxDetached (Key key) (Nonce nonce) msg =
  buildUnsafeByteString ctLen $ \pc ->
   fmap snd . buildUnsafeByteString' tagLen $ \ptag ->
    constByteStrings [key, msg, nonce] $ \
      [(pk, _), (pmsg, _), (pn, _)] ->
        c_secretbox_detached pc ptag pmsg (fromIntegral ptLen) pn pk
  where ctLen  = ptLen
        ptLen  = S.length msg
        tagLen = Bytes.secretBoxMac

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
  where len    = S.length cipher + Bytes.secretBoxBoxZero
        pad'   = pad Bytes.secretBoxBoxZero
        unpad' = unpad Bytes.secretBoxZero

-- | Decrypts a message. Returns 'Nothing' if the keys and message do
-- not match.
secretboxOpenDetached
    :: Key
    -> Nonce
    -> ByteString
    -- ^ Auth Tag
    -> ByteString
    -- ^ Ciphertext
    -> Maybe ByteString
    -- ^ Message
secretboxOpenDetached (Key key) (Nonce nonce) tag cipher
    | S.length tag /= Bytes.secretBoxMac = Nothing
    | otherwise =
  let (err, vec) = buildUnsafeByteString len $ \pm ->
        constByteStrings [key, cipher, tag, nonce] $ \
          [(pk, _), (pc, _), (pt, _), (pn, _)] ->
            c_secretbox_open_detached pm pc pt (fromIntegral len) pn pk
  in hush . handleErrno err $ vec
  where len    = S.length cipher

-- | The secretbox C API uses 0-padded C strings. Always returns 0.
foreign import ccall "crypto_secretbox"
  c_secretbox
    :: Ptr CChar
    -- ^ Cipher 0-padded output buffer
    -> Ptr CChar
    -- ^ Constant 0-padded message input buffer
    -> CULLong
    -- ^ Length of message input buffer (incl. 0s)
    -> Ptr CChar
    -- ^ Constant nonce buffer
    -> Ptr CChar
    -- ^ Constant key buffer
    -> IO CInt

-- | The secretbox_detached C API uses C strings. Always returns 0.
foreign import ccall "crypto_secretbox_detached"
  c_secretbox_detached
    :: Ptr CChar
    -- ^ Ciphertext output buffer
    -> Ptr CChar
    -- ^ Authentication tag output buffer
    -> Ptr CChar
    -- ^ Constant message input buffer
    -> CULLong
    -- ^ Length of message input buffer (incl. 0s)
    -> Ptr CChar
    -- ^ Constant nonce buffer
    -> Ptr CChar
    -- ^ Constant key buffer
    -> IO CInt

-- | The secretbox C API uses 0-padded C strings. Returns 0 if
-- successful or -1 if verification failed.
foreign import ccall "crypto_secretbox_open"
  c_secretbox_open
    :: Ptr CChar
    -- ^ Message 0-padded output buffer
    -> Ptr CChar
    -- ^ Constant 0-padded message input buffer
    -> CULLong
    -- ^ Length of message input buffer (incl. 0s)
    -> Ptr CChar
    -- ^ Constant nonce buffer
    -> Ptr CChar
    -- ^ Constant key buffer
    -> IO CInt

-- | The secretbox C API uses C strings. Returns 0 if
-- successful or -1 if verification failed.
foreign import ccall "crypto_secretbox_open_detached"
  c_secretbox_open_detached
    :: Ptr CChar
    -- ^ Message output buffer
    -> Ptr CChar
    -- ^ Constant ciphertext input buffer
    -> Ptr CChar
    -- ^ Constant auth tag input buffer
    -> CULLong
    -- ^ Length of ciphertext input buffer
    -> Ptr CChar
    -- ^ Constant nonce buffer
    -> Ptr CChar
    -- ^ Constant key buffer
    -> IO CInt

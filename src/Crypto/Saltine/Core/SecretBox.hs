{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Crypto.Saltine.Core.SecretBox
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
-- 
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Secret-key authenticated encryption:
-- "Crypto.Saltine.Core.SecretBox"
-- 
-- The 'secretbox' function encrypts and authenticates a message
-- 'V.Vector' using a secret key and a nonce. The 'secretboxOpen'
-- function verifies and decrypts a ciphertext 'V.Vector' using a secret
-- key and a nonce. If the ciphertext fails validation,
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
  newKey, newNonce
  ) where

import Crypto.Saltine.Class
import Crypto.Saltine.Core.Hash (hash)
import Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import Foreign.C
import Foreign.Ptr
import Data.Word
import qualified Data.ByteString.Char8 as S8
import qualified Data.Vector.Storable as V

import Control.Applicative
import Control.Monad

-- $types

-- | An opaque 'secretbox' cryptographic key.
newtype Key = Key (V.Vector Word8) deriving (Eq, Ord)

instance Show Key where
  show k = "SecretBox.Key {hashesTo = \""
           ++ (take 10 $ S8.unpack $ ashex $ hash k)
           ++ "...\"}"

instance IsEncoding Key where
  decode v = case V.length v == Bytes.secretBoxKey of
    True -> Just (Key v)
    False -> Nothing
  {-# INLINE decode #-}
  encode (Key v) = v
  {-# INLINE encode #-}

-- | An opaque 'secretbox' nonce.
newtype Nonce = Nonce (V.Vector Word8) deriving (Eq, Ord)

instance Show Nonce where show = ashexShow "SecretBox.Nonce"

instance IsEncoding Nonce where
  decode v = case V.length v == Bytes.secretBoxNonce of
    True -> Just (Nonce v)
    False -> Nothing
  {-# INLINE decode #-}
  encode (Nonce v) = v
  {-# INLINE encode #-}

instance IsNonce Nonce where
  zero = Nonce (V.replicate Bytes.secretBoxNonce 0)
  nudge (Nonce n) = Nonce (nudgeVector n)

-- | Creates a random key of the correct size for 'secretbox'.
newKey :: IO Key
newKey = Key <$> randomVector Bytes.secretBoxKey

-- | Creates a random nonce of the correct size for 'secretbox'.
newNonce :: IO Nonce
newNonce = Nonce <$> randomVector Bytes.secretBoxNonce

-- | Encrypts a message. It is infeasible for an attacker to decrypt
-- the message so long as the 'Nonce' is never repeated.
secretbox :: IsEncoding a => Key -> Nonce -> a -> V.Vector Word8
secretbox (Key key) (Nonce nonce) encmsg =
  unpad' . snd . buildUnsafeCVector len $ \pc ->
    constVectors [key, pad' msg, nonce] $ \[pk, pm, pn] ->
    c_secretbox pc pm (fromIntegral len) pn pk
  where len    = V.length msg + Bytes.secretBoxZero
        pad'   = pad Bytes.secretBoxZero
        unpad' = unpad Bytes.secretBoxBoxZero
        msg    = encode encmsg

-- | Decrypts a message. Returns 'Nothing' if the keys and message do
-- not match.
secretboxOpen :: (IsEncoding a, IsEncoding b) => Key -> Nonce -> a -> Maybe b
secretboxOpen (Key key) (Nonce nonce) enccipher =
  let (err, vec) = buildUnsafeCVector len $ \pm ->
        constVectors [key, pad' cipher, nonce] $ \[pk, pc, pn] ->
        c_secretbox_open pm pc (fromIntegral len) pn pk
  in decode <=< hush . handleErrno err $ unpad' vec
  where len    = V.length cipher + Bytes.secretBoxBoxZero
        pad'   = pad Bytes.secretBoxBoxZero
        unpad' = unpad Bytes.secretBoxZero
        cipher = encode enccipher

-- | The secretbox C API uses 0-padded C strings. Always returns 0.
foreign import ccall "crypto_secretbox"
  c_secretbox :: Ptr Word8
                 -- ^ Cipher 0-padded output buffer
                 -> Ptr Word8
                 -- ^ Constant 0-padded message input buffer
                 -> CULLong
                 -- ^ Length of message input buffer (incl. 0s)
                 -> Ptr Word8
                 -- ^ Constant nonce buffer
                 -> Ptr Word8
                 -- ^ Constant key buffer
                 -> IO CInt

-- | The secretbox C API uses 0-padded C strings. Returns 0 if
-- successful or -1 if verification failed.
foreign import ccall "crypto_secretbox_open"
  c_secretbox_open :: Ptr Word8
                      -- ^ Message 0-padded output buffer
                      -> Ptr Word8
                      -- ^ Constant 0-padded message input buffer
                      -> CULLong
                      -- ^ Length of message input buffer (incl. 0s)
                      -> Ptr Word8
                      -- ^ Constant nonce buffer
                      -> Ptr Word8
                      -- ^ Constant key buffer
                      -> IO CInt
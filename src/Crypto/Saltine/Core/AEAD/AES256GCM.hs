{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, DeriveGeneric #-}

-- |
-- Module      : Crypto.Saltine.Core.AEAD.AES256GCM
-- Copyright   : (c) Thomas DuBuisson 2017
--               (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
-- Secret-key authenticated encryption with additional data (AEAD):
-- "Crypto.Saltine.Core.AEAD.AES256GCM"
--
-- Using this module is not recommended. Don't use unless you have to.
-- Keep in mind its limitations: https://doc.libsodium.org/secret-key_cryptography/aead
--
-- Unless you know for certain the CPU your program will run on supports
-- Intel SSSE3, AES-NI and CLMUL, you should run @aead_aes256gcm_available@
-- first and only proceed if the result is True.
--
-- Generating nonces for the functions in this module randomly
-- is not recommended, due to the risk of generating collisions.

module Crypto.Saltine.Core.AEAD.AES256GCM (
  Key, Nonce,
  aead_aes256gcm_available,
  aead, aeadOpen,
  aeadDetached, aeadOpenDetached,
  newKey, newNonce
  ) where

import           Crypto.Saltine.Class
import           Crypto.Saltine.Internal.Util           as U
import qualified Crypto.Saltine.Internal.AEAD.AES256GCM as Bytes
import           Crypto.Saltine.Internal.AEAD.AES256GCM (c_aead_aes256gcm_is_available, c_aead, c_aead_open, c_aead_detached, c_aead_open_detached)

import           Control.Applicative
import           Control.DeepSeq
import           Foreign.C
import           Foreign.Ptr
import qualified Data.ByteString                   as S
import           Data.ByteString                    (ByteString)
import           Data.Hashable                      (Hashable)
import           Data.Data                          (Data, Typeable)
import           GHC.Generics                       (Generic)
import           System.IO.Unsafe                   (unsafePerformIO)

-- $types

-- | An opaque 'AES256GCM' cryptographic key.
newtype Key = Key ByteString deriving (Ord, Hashable, Data, Typeable, Generic, NFData)
instance Eq Key where
    Key a == Key b = U.compare a b

instance IsEncoding Key where
  decode v = if S.length v == Bytes.aead_aes256gcm_keybytes
           then Just (Key v)
           else Nothing
  {-# INLINE decode #-}
  encode (Key v) = v
  {-# INLINE encode #-}

-- | An opaque 'AES256GCM' nonce.
newtype Nonce = Nonce ByteString deriving (Eq, Ord, Hashable, Data, Typeable, Generic, NFData)

instance IsEncoding Nonce where
  decode v = if S.length v == Bytes.aead_aes256gcm_npubbytes
           then Just (Nonce v)
           else Nothing
  {-# INLINE decode #-}
  encode (Nonce v) = v
  {-# INLINE encode #-}

instance IsNonce Nonce where
  zero            = Nonce (S.replicate Bytes.aead_aes256gcm_npubbytes 0)
  nudge (Nonce n) = Nonce (nudgeBS n)

-- | Creates a random 'AES256GCM' key
newKey :: IO Key
newKey = Key <$> randomByteString Bytes.aead_aes256gcm_keybytes

-- | Creates a random 'AES256GCM' nonce
newNonce :: IO Nonce
newNonce = Nonce <$> randomByteString Bytes.aead_aes256gcm_npubbytes


{-# NOINLINE aead_aes256gcm_available #-}
aead_aes256gcm_available :: Bool
aead_aes256gcm_available =
    unsafePerformIO c_aead_aes256gcm_is_available == 1

-- | Encrypts a message. It is infeasible for an attacker to decrypt
-- the message so long as the 'Nonce' is never repeated.
aead
    :: Key
    -> Nonce
    -> ByteString
    -- ^ Message
    -> ByteString
    -- ^ AAD
    -> ByteString
    -- ^ Ciphertext
aead (Key key) (Nonce nonce) msg aad =
  snd . buildUnsafeByteString clen $ \pc ->
    constByteStrings [key, msg, aad, nonce] $ \
      [(pk, _), (pm, _), (pa, _), (pn, _)] ->
          c_aead pc nullPtr pm (fromIntegral mlen) pa (fromIntegral alen) nullPtr pn pk
  where mlen    = S.length msg
        alen    = S.length aad
        clen    = mlen + Bytes.aead_aes256gcm_abytes

-- | Decrypts a message. Returns 'Nothing' if the keys and message do
-- not match.
aeadOpen
    :: Key
    -> Nonce
    -> ByteString
    -- ^ Ciphertext
    -> ByteString
    -- ^ AAD
    -> Maybe ByteString
    -- ^ Message
aeadOpen (Key key) (Nonce nonce) cipher aad = do
  let clen   = S.length cipher
      alen   = S.length aad
  mlen <- clen `safeSubtract` Bytes.aead_aes256gcm_abytes
  let (err, vec) = buildUnsafeByteString mlen $ \pm ->
        constByteStrings [key, cipher, aad, nonce] $ \
          [(pk, _), (pc, _), (pa, _), (pn, _)] ->
            c_aead_open pm nullPtr nullPtr pc (fromIntegral clen) pa (fromIntegral alen) pn pk
  hush . handleErrno err $ vec

-- | Encrypts a message. It is infeasible for an attacker to decrypt
-- the message so long as the 'Nonce' is never repeated.
aeadDetached
    :: Key
    -> Nonce
    -> ByteString
    -- ^ Message
    -> ByteString
    -- ^ AAD
    -> (ByteString,ByteString)
    -- ^ Tag, Ciphertext
aeadDetached (Key key) (Nonce nonce) msg aad =
  buildUnsafeByteString clen $ \pc ->
   fmap snd . buildUnsafeByteString' tlen $ \pt ->
    constByteStrings [key, msg, aad, nonce] $ \
      [(pk, _), (pm, _), (pa, _), (pn, _)] ->
          c_aead_detached pc pt nullPtr pm (fromIntegral mlen) pa (fromIntegral alen) nullPtr pn pk
  where mlen    = S.length msg
        alen    = S.length aad
        clen    = mlen
        tlen    = Bytes.aead_aes256gcm_abytes

-- | Decrypts a message. Returns 'Nothing' if the keys and message do
-- not match.
aeadOpenDetached
    :: Key
    -> Nonce
    -> ByteString
    -- ^ Tag
    -> ByteString
    -- ^ Ciphertext
    -> ByteString
    -- ^ AAD
    -> Maybe ByteString
    -- ^ Message
aeadOpenDetached (Key key) (Nonce nonce) tag cipher aad
    | S.length tag /= tlen = Nothing
    | otherwise =
  let (err, vec) = buildUnsafeByteString len $ \pm ->
        constByteStrings [key, tag, cipher, aad, nonce] $ \
          [(pk, _), (pt, _), (pc, _), (pa, _), (pn, _)] ->
            c_aead_open_detached pm nullPtr pc (fromIntegral len) pt pa (fromIntegral alen) pn pk
  in hush . handleErrno err $ vec
  where len    = S.length cipher
        alen   = S.length aad
        tlen   = Bytes.aead_aes256gcm_abytes

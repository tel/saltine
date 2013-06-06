-- |
-- Module      : Crypto.Saltine.Core.Stream
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
-- 
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Secret-key encryption:
-- "Crypto.Saltine.Core.Stream"
-- 
-- The 'stream' function produces a sized stream 'V.Vector' as a
-- function of a secret key and a nonce. The 'xor' function encrypts a
-- message 'V.Vector' using a secret key and a nonce.  The 'xor'
-- function guarantees that the ciphertext has the same length as the
-- plaintext, and is the @plaintext `xor` stream k n@. Consequently
-- 'xor' can also be used to decrypt.
-- 
-- The 'stream' function, viewed as a function of the nonce for a
-- uniform random key, is designed to meet the standard notion of
-- unpredictability (\"PRF\"). For a formal definition see, e.g.,
-- Section 2.3 of Bellare, Kilian, and Rogaway, \"The security of the
-- cipher block chaining message authentication code,\" Journal of
-- Computer and System Sciences 61 (2000), 362–399;
-- <http://www-cse.ucsd.edu/~mihir/papers/cbc.html>. This means that
-- an attacker cannot distinguish this function from a uniform random
-- function. Consequently, if a series of messages is encrypted by
-- 'xor' with /a different nonce for each message/, the ciphertexts
-- are indistinguishable from uniform random strings of the same
-- length.
-- 
-- Note that the length is not hidden. Note also that it is the
-- caller's responsibility to ensure the uniqueness of nonces—for
-- example, by using nonce 1 for the first message, nonce 2 for the
-- second message, etc. Nonces are long enough that randomly generated
-- nonces have negligible risk of collision.
-- 
-- Saltine does not make any promises regarding the resistance of
-- crypto_stream to \"related-key attacks.\" It is the caller's
-- responsibility to use proper key-derivation functions.
-- 
-- "Crypto.Saltine.Core.Stream" is @crypto_stream_xsalsa20@, a
-- particular cipher specified in \"Cryptography in NaCl\"
-- (<http://nacl.cr.yp.to/valid.html>), Section 7. This cipher is
-- conjectured to meet the standard notion of unpredictability.
-- 
-- This is version 2010.08.30 of the stream.html web page.

module Crypto.Saltine.Core.Stream (
  Key, Nonce,
  newKey, newNonce,
  stream, xor
  ) where

import Crypto.Saltine.Class
import Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import Foreign.C
import Foreign.Ptr
import Data.Word
import qualified Data.Vector.Storable as V

import Control.Applicative

-- $types

-- | An opaque 'stream' cryptographic key.
newtype Key = Key (V.Vector Word8) deriving (Eq, Ord)

instance IsEncoding Key where
  decode v = case V.length v == Bytes.streamKey of
    True -> Just (Key v)
    False -> Nothing
  {-# INLINE decode #-}
  encode (Key v) = v
  {-# INLINE encode #-}

-- | An opaque 'stream' nonce.
newtype Nonce = Nonce (V.Vector Word8) deriving (Eq, Ord)
-- TODO: Enum for Nonce

instance IsEncoding Nonce where
  decode v = case V.length v == Bytes.streamNonce of
    True -> Just (Nonce v)
    False -> Nothing
  {-# INLINE decode #-}
  encode (Nonce v) = v
  {-# INLINE encode #-}

-- | Creates a random key of the correct size for 'stream' and 'xor'.
newKey :: IO Key
newKey = Key <$> randomVector Bytes.streamKey

-- | Creates a random nonce of the correct size for 'stream' and
-- 'xor'.
newNonce :: IO Nonce
newNonce = Nonce <$> randomVector Bytes.streamNonce

-- | Executes @crypto_stream@ on the passed 'V.Vector's. THIS IS
-- MEMORY UNSAFE unless the key and nonce are precisely the right
-- sizes.
stream :: Key -> Nonce -> Int
          -> V.Vector Word8
          -- ^ Cryptographic stream
stream (Key key) (Nonce nonce) n =
  snd . buildUnsafeCVector n $ \ps ->
    constVectors [key, nonce] $ \[pk, pn] ->
    c_stream ps (fromIntegral n) pn pk

-- | Executes @crypto_stream_xor@ on the passed 'V.Vector's. THIS IS
-- MEMORY UNSAFE unless the key and nonce are precisely the right
-- sizes.
xor :: Key -> Nonce 
       -> V.Vector Word8
       -- ^ Message
       -> V.Vector Word8
       -- ^ Ciphertext
xor (Key key) (Nonce nonce) msg =
  snd . buildUnsafeCVector len $ \pc ->
    constVectors [key, nonce, msg] $ \[pk, pn, pm] ->
    c_stream_xor pc pm (fromIntegral len) pn pk
  where len = V.length msg

foreign import ccall "crypto_stream"
  c_stream :: Ptr Word8
              -- ^ Stream output buffer
              -> CULLong
              -- ^ Length of stream to generate
              -> Ptr Word8
              -- ^ Constant nonce buffer
              -> Ptr Word8
              -- ^ Constant key buffer
              -> IO CInt
              -- ^ Always 0

foreign import ccall "crypto_stream_xor"
  c_stream_xor :: Ptr Word8
                  -- ^ Ciphertext output buffer
                  -> Ptr Word8
                  -- ^ Constant message buffer
                  -> CULLong
                  -- ^ Length of message buffer
                  -> Ptr Word8
                  -- ^ Constant nonce buffer
                  -> Ptr Word8
                  -- ^ Constant key buffer
                  -> IO CInt
                  -- ^ Always 0
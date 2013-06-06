-- |
-- Module      : Crypto.Saltine.Internal.Stream
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
-- 
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Secret-key encryption:
-- "Crypto.Saltine.Internal.Stream"
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
-- "Crypto.Saltine.Internal.Stream" is @crypto_stream_xsalsa20@, a
-- particular cipher specified in \"Cryptography in NaCl\"
-- (<http://nacl.cr.yp.to/valid.html>), Section 7. This cipher is
-- conjectured to meet the standard notion of unpredictability.
-- 
-- This is version 2010.08.30 of the stream.html web page.

module Crypto.Saltine.Internal.Stream where

import Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import Foreign.C
import Foreign.Ptr
import Data.Word
import qualified Data.Vector.Storable as V

-- | Creates a random nonce of the correct size for 'stream' and
-- 'xor'.
newNonce :: IO (V.Vector Word8)
newNonce = randomVector Bytes.streamNonce

-- | Creates a random key of the correct size for 'stream' and 'xor'.
newKey :: IO (V.Vector Word8)
newKey = randomVector Bytes.streamKey

-- | Executes @crypto_stream@ on the passed 'V.Vector's. THIS IS
-- MEMORY UNSAFE unless the key and nonce are precisely the right
-- sizes.
stream :: V.Vector Word8
          -- ^ Key
          -> V.Vector Word8
          -- ^ Nonce
          -> Int
          -- ^ Length of vector to generate
          -> V.Vector Word8
          -- ^ Cryptographic stream
stream key nonce n =
  snd . buildUnsafeCVector n $ \ps ->
    constVectors [key, nonce] $ \[pk, pn] ->
    c_stream ps (fromIntegral n) pn pk

-- | Executes @crypto_stream_xor@ on the passed 'V.Vector's. THIS IS
-- MEMORY UNSAFE unless the key and nonce are precisely the right
-- sizes.
xor :: V.Vector Word8
       -- ^ Key
       -> V.Vector Word8
       -- ^ Nonce
       -> V.Vector Word8
       -- ^ Message
       -> V.Vector Word8
       -- ^ Ciphertext
xor key nonce msg =
  snd . buildUnsafeCVector len $ \pc ->
    constVectors [key, nonce, msg] $ \[pk, pn, pm] ->
    c_stream_xor pc pm (fromIntegral len) pn pk
  where len = V.length msg

foreign import ccall "crypto_stream"
  c_stream :: Ptr Word8
              -- ^ Stream output buffer
              -> CInt
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
                  -> CInt
                  -- ^ Length of message buffer
                  -> Ptr Word8
                  -- ^ Constant nonce buffer
                  -> Ptr Word8
                  -- ^ Constant key buffer
                  -> IO CInt
                  -- ^ Always 0
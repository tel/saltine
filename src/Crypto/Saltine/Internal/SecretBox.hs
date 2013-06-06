-- |
-- Module      : Crypto.Saltine.Internal.SecretBox
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
-- 
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Secret-key authenticated encryption:
-- "Crypto.Saltine.Internal.SecretBox"
-- 
-- The 'secretbox' function encrypts and authenticates a message
-- 'V.Vector' using a secret key and a nonce. The 'secretboxOpen'
-- function verifies and decrypts a ciphertext 'V.Vector' using a secret
-- key and a nonce. If the ciphertext fails validation,
-- 'secretboxOpen' returns 'Nothing'.
-- 
-- The "Crypto.Saltine.Internal.SecretBox" module is designed to meet
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
-- "Crypto.Saltine.Internal.SecretBox" is
-- @crypto_secretbox_xsalsa20poly1305@, a particular combination of
-- Salsa20 and Poly1305 specified in \"Cryptography in NaCl\"
-- (<http://nacl.cr.yp.to/valid.html>). This function is conjectured
-- to meet the standard notions of privacy and authenticity.
-- 
-- This is version 2010.08.30 of the secretbox.html web page.
module Crypto.Saltine.Internal.SecretBox (
  secretbox, secretboxOpen,
  newKey, newNonce
  ) where

import Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import Foreign.C
import Foreign.Ptr
import Data.Word
import qualified Data.Vector.Storable as V

-- | Executes @crypto_secretbox@ on the passed 'V.Vector's. THIS IS
-- MEMORY UNSAFE unless the key and nonce are precisely the right
-- sizes.
secretbox :: V.Vector Word8
             -- ^ Key
             -> V.Vector Word8
             -- ^ Nonce
             -> V.Vector Word8
             -- ^ Message
             -> V.Vector Word8
             -- ^ Ciphertext
secretbox key nonce msg =
  unpad' . snd . buildUnsafeCVector len $ \pc ->
    constVectors [key, pad' msg, nonce] $ \[pk, pm, pn] ->
    c_secretbox pc pm (fromIntegral len) pn pk
  where len    = V.length msg + Bytes.secretBoxZero
        pad'   = pad Bytes.secretBoxZero
        unpad' = unpad Bytes.secretBoxBoxZero

-- | Executes @crypto_secretbox_open@ on the passed 'V.Vector's. THIS
-- IS MEMORY UNSAFE unless the key and nonce are precisely the right
-- sizes.
secretboxOpen :: V.Vector Word8
                 -- ^ Key
                 -> V.Vector Word8
                 -- ^ Nonce
                 -> V.Vector Word8
                 -- ^ Ciphertext
                 -> Maybe (V.Vector Word8)
                 -- ^ Message
secretboxOpen key nonce cipher =
  let (err, vec) = buildUnsafeCVector len $ \pm ->
        constVectors [key, pad' cipher, nonce] $ \[pk, pc, pn] ->
        c_secretbox_open pm pc (fromIntegral len) pn pk
  in hush . handleErrno err $ unpad' vec
  where len    = V.length cipher + Bytes.secretBoxBoxZero
        pad'   = pad Bytes.secretBoxBoxZero
        unpad' = unpad Bytes.secretBoxZero

-- | Creates a random nonce of the correct size for 'secretbox'.
newNonce :: IO (V.Vector Word8)
newNonce = randomVector Bytes.secretBoxNonce

-- | Creates a random key of the correct size for 'secretbox'.
newKey :: IO (V.Vector Word8)
newKey = randomVector Bytes.secretBoxKey


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
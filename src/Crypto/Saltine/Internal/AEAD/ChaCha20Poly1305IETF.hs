{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.AEAD.ChaCha20Poly1305IETF
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.AEAD.ChaCha20Poly1305IETF (
    aead_chacha20poly1305_ietf_keybytes
  , aead_chacha20poly1305_ietf_npubbytes
  , aead_chacha20poly1305_ietf_abytes
  , c_aead
  , c_aead_open
  , c_aead_detached
  , c_aead_open_detached
) where

import Foreign.C
import Foreign.Ptr

aead_chacha20poly1305_ietf_keybytes, aead_chacha20poly1305_ietf_abytes, aead_chacha20poly1305_ietf_npubbytes :: Int

-- | Size of a ChaCha20-Poly1305-IETF key
aead_chacha20poly1305_ietf_keybytes  = fromIntegral c_crypto_aead_chacha20poly1305_ietf_keybytes
-- | Size of a ChaCha20-Poly1305-IETF nonce
aead_chacha20poly1305_ietf_npubbytes = fromIntegral c_crypto_aead_chacha20poly1305_ietf_npubbytes
-- | Size of a ChaCha20-Poly1305-IETF authentication tag
aead_chacha20poly1305_ietf_abytes    = fromIntegral c_crypto_aead_chacha20poly1305_ietf_abytes


-- src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c
-- src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h
foreign import ccall "crypto_aead_chacha20poly1305_ietf_keybytes"
    c_crypto_aead_chacha20poly1305_ietf_keybytes :: CSize
foreign import ccall "crypto_aead_chacha20poly1305_ietf_npubbytes"
    c_crypto_aead_chacha20poly1305_ietf_npubbytes:: CSize
foreign import ccall "crypto_aead_chacha20poly1305_ietf_abytes"
    c_crypto_aead_chacha20poly1305_ietf_abytes :: CSize


-- | The aead C API uses C strings. Always returns 0.
foreign import ccall "crypto_aead_chacha20poly1305_ietf_encrypt"
  c_aead
    :: Ptr CChar
    -- ^ Cipher output buffer
    -> Ptr CULLong
    -- ^ Cipher output bytes used
    -> Ptr CChar
    -- ^ Constant message input buffer
    -> CULLong
    -- ^ Length of message input buffer
    -> Ptr CChar
    -- ^ Constant aad input buffer
    -> CULLong
    -- ^ Length of aad input buffer
    -> Ptr CChar
    -- ^ Unused 'nsec' value (must be NULL)
    -> Ptr CChar
    -- ^ Constant nonce buffer
    -> Ptr CChar
    -- ^ Constant key buffer
    -> IO CInt

-- | The aead open C API uses C strings. Returns 0 if successful.
foreign import ccall "crypto_aead_chacha20poly1305_ietf_decrypt"
  c_aead_open
    :: Ptr CChar
    -- ^ Message output buffer
    -> Ptr CULLong
    -- ^ Message output bytes used
    -> Ptr CChar
    -- ^ Unused 'nsec' value (must be NULL)
    -> Ptr CChar
    -- ^ Constant ciphertext input buffer
    -> CULLong
    -- ^ Length of ciphertext input buffer
    -> Ptr CChar
    -- ^ Constant aad input buffer
    -> CULLong
    -- ^ Length of aad input buffer
    -> Ptr CChar
    -- ^ Constant nonce buffer
    -> Ptr CChar
    -- ^ Constant key buffer
    -> IO CInt

-- | The aead C API uses C strings. Always returns 0.
foreign import ccall "crypto_aead_chacha20poly1305_ietf_encrypt_detached"
  c_aead_detached
    :: Ptr CChar
    -- ^ Cipher output buffer
    -> Ptr CChar
    -- ^ Tag output buffer
    -> Ptr CULLong
    -- ^ Tag bytes used
    -> Ptr CChar
    -- ^ Constant message input buffer
    -> CULLong
    -- ^ Length of message input buffer
    -> Ptr CChar
    -- ^ Constant aad input buffer
    -> CULLong
    -- ^ Length of aad input buffer
    -> Ptr CChar
    -- ^ Unused 'nsec' value (must be NULL)
    -> Ptr CChar
    -- ^ Constant nonce buffer
    -> Ptr CChar
    -- ^ Constant key buffer
    -> IO CInt

-- | The aead open C API uses C strings. Returns 0 if successful.
foreign import ccall "crypto_aead_chacha20poly1305_ietf_decrypt_detached"
  c_aead_open_detached
    :: Ptr CChar
    -- ^ Message output buffer
    -> Ptr CChar
    -- ^ Unused 'nsec' value (must be NULL)
    -> Ptr CChar
    -- ^ Constant ciphertext input buffer
    -> CULLong
    -- ^ Length of ciphertext input buffer
    -> Ptr CChar
    -- ^ Constant tag input buffer
    -> Ptr CChar
    -- ^ Constant aad input buffer
    -> CULLong
    -- ^ Length of aad input buffer
    -> Ptr CChar
    -- ^ Constant nonce buffer
    -> Ptr CChar
    -- ^ Constant key buffer
    -> IO CInt

{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.AEAD.ChaCha20Poly1305
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.AEAD.ChaCha20Poly1305 (
    aead_chacha20poly1305_keybytes
  , aead_chacha20poly1305_npubbytes
  , aead_chacha20poly1305_abytes
  , c_aead
  , c_aead_open
  , c_aead_detached
  , c_aead_open_detached
) where

import Foreign.C
import Foreign.Ptr

aead_chacha20poly1305_keybytes, aead_chacha20poly1305_abytes, aead_chacha20poly1305_npubbytes :: Int

-- | Size of a ChaCha20-Poly1305 key
aead_chacha20poly1305_keybytes  = fromIntegral c_crypto_aead_chacha20poly1305_keybytes
-- | Size of a ChaCha20-Poly1305 nonce
aead_chacha20poly1305_npubbytes = fromIntegral c_crypto_aead_chacha20poly1305_npubbytes
-- | Size of a ChaCha20-Poly1305 authentication tag
aead_chacha20poly1305_abytes    = fromIntegral c_crypto_aead_chacha20poly1305_abytes


-- src/libsodium/crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c
-- src/libsodium/include/sodium/crypto_aead_xchacha20poly1305.h
foreign import ccall "crypto_aead_chacha20poly1305_keybytes"
    c_crypto_aead_chacha20poly1305_keybytes :: CSize
foreign import ccall "crypto_aead_chacha20poly1305_npubbytes"
    c_crypto_aead_chacha20poly1305_npubbytes:: CSize
foreign import ccall "crypto_aead_chacha20poly1305_abytes"
    c_crypto_aead_chacha20poly1305_abytes :: CSize


-- | The aead C API uses C strings. Always returns 0.
foreign import ccall "crypto_aead_chacha20poly1305_encrypt"
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
foreign import ccall "crypto_aead_chacha20poly1305_decrypt"
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
foreign import ccall "crypto_aead_chacha20poly1305_encrypt_detached"
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
foreign import ccall "crypto_aead_chacha20poly1305_decrypt_detached"
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

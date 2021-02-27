{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.SecretBox
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.SecretBox (
  secretBoxKey,
  secretBoxNonce,
  secretBoxMac,
  secretBoxZero,
  secretBoxBoxZero,
  c_secretbox,
  c_secretbox_detached,
  c_secretbox_open,
  c_secretbox_open_detached
) where

import Foreign.C
import Foreign.Ptr

secretBoxKey, secretBoxNonce, secretBoxMac, secretBoxZero, secretBoxBoxZero :: Int

-- SecretBox
-- | Size of a @crypto_secretbox@ secret key
secretBoxKey     = fromIntegral c_crypto_secretbox_keybytes
-- | Size of a @crypto_secretbox@ nonce
secretBoxNonce   = fromIntegral c_crypto_secretbox_noncebytes
-- | Size of a @crypto_secretbox@ mac
secretBoxMac     = fromIntegral c_crypto_secretbox_macbytes
-- | Size of 0-padding prepended to messages before using
-- @crypto_secretbox@ or after using @crypto_secretbox_open@
secretBoxZero    = fromIntegral c_crypto_secretbox_zerobytes
-- | Size of 0-padding prepended to ciphertext before using
-- @crypto_secretbox_open@ or after using @crypto_secretbox@
secretBoxBoxZero = fromIntegral c_crypto_secretbox_boxzerobytes

-- src/libsodium/crypto_secretbox/crypto_secretbox.c
foreign import ccall "crypto_secretbox_keybytes"
  c_crypto_secretbox_keybytes :: CSize
foreign import ccall "crypto_secretbox_noncebytes"
  c_crypto_secretbox_noncebytes :: CSize
foreign import ccall "crypto_secretbox_macbytes"
  c_crypto_secretbox_macbytes :: CSize
foreign import ccall "crypto_secretbox_zerobytes"
  c_crypto_secretbox_zerobytes :: CSize
foreign import ccall "crypto_secretbox_boxzerobytes"
  c_crypto_secretbox_boxzerobytes :: CSize

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

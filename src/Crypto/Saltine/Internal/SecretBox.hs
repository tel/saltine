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
  secretBoxBoxZero
) where

import Foreign.C

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

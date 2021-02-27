{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.ScalarMult
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.ScalarMult (
    mult
  , multScalar
  , c_scalarmult
  , c_scalarmult_base
) where

import Foreign.C
import Foreign.Ptr

mult, multScalar :: Int

-- ScalarMult
-- | Size of a group element string representation for
-- @crypto_scalarmult@.
mult = fromIntegral c_crypto_scalarmult_bytes
-- | Size of a integer string representation for @crypto_scalarmult@.
multScalar = fromIntegral c_crypto_scalarmult_scalarbytes

-- src/libsodium/crypto_scalarmult/crypto_scalarmult.c
foreign import ccall "crypto_scalarmult_bytes"
  c_crypto_scalarmult_bytes :: CSize
foreign import ccall "crypto_scalarmult_scalarbytes"
  c_crypto_scalarmult_scalarbytes :: CSize

foreign import ccall "crypto_scalarmult"
  c_scalarmult :: Ptr CChar
               -- ^ Output group element buffer
               -> Ptr CChar
               -- ^ Input integer buffer
               -> Ptr CChar
               -- ^ Input group element buffer
               -> IO CInt
               -- ^ Always 0

foreign import ccall "crypto_scalarmult_base"
  c_scalarmult_base :: Ptr CChar
                    -- ^ Output group element buffer
                    -> Ptr CChar
                    -- ^ Input integer buffer
                    -> IO CInt
                    -- ^ Always 0

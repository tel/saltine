{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.OneTimeAuth
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.OneTimeAuth (
    onetime
  , onetimeKey
  , c_onetimeauth
  , c_onetimeauth_verify
) where

import Foreign.C
import Foreign.Ptr

onetime, onetimeKey :: Int

-- OneTimeAuth
-- | Size of a @crypto_onetimeauth@ authenticator.
onetime    = fromIntegral c_crypto_onetimeauth_bytes
-- | Size of a @crypto_onetimeauth@ authenticator key.
onetimeKey = fromIntegral c_crypto_onetimeauth_keybytes

-- src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c
foreign import ccall "crypto_onetimeauth_bytes"
  c_crypto_onetimeauth_bytes :: CSize
foreign import ccall "crypto_onetimeauth_keybytes"
  c_crypto_onetimeauth_keybytes :: CSize


foreign import ccall "crypto_onetimeauth"
  c_onetimeauth :: Ptr CChar
                -- ^ Authenticator output buffer
                -> Ptr CChar
                -- ^ Constant message buffer
                -> CULLong
                -- ^ Length of message buffer
                -> Ptr CChar
                -- ^ Constant key buffer
                -> IO CInt
                -- ^ Always 0

-- | We don't even include this in the IO monad since all of the
-- buffers are constant.
foreign import ccall "crypto_onetimeauth_verify"
  c_onetimeauth_verify :: Ptr CChar
                       -- ^ Constant authenticator buffer
                       -> Ptr CChar
                       -- ^ Constant message buffer
                       -> CULLong
                       -- ^ Length of message buffer
                       -> Ptr CChar
                       -- ^ Constant key buffer
                       -> CInt
                       -- ^ Success if 0, failure if -1

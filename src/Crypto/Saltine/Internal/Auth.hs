{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.Auth
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.Auth (
    auth
  , authKey
  , c_auth
  , c_auth_verify
) where

import Foreign.C
import Foreign.Ptr

auth, authKey :: Int

-- Authentication
-- | Size of a @crypto_auth@ authenticator.
auth    = fromIntegral c_crypto_auth_bytes
-- | Size of a @crypto_auth@ authenticator key.
authKey = fromIntegral c_crypto_auth_keybytes

-- src/libsodium/crypto_auth/crypto_auth.c
foreign import ccall "crypto_auth_bytes"
  c_crypto_auth_bytes :: CSize
foreign import ccall "crypto_auth_keybytes"
  c_crypto_auth_keybytes :: CSize

foreign import ccall "crypto_auth"
  c_auth :: Ptr CChar
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
foreign import ccall "crypto_auth_verify"
  c_auth_verify :: Ptr CChar
                -- ^ Constant authenticator buffer
                -> Ptr CChar
                -- ^ Constant message buffer
                -> CULLong
                -- ^ Length of message buffer
                -> Ptr CChar
                -- ^ Constant key buffer
                -> CInt
                -- ^ Success if 0, failure if -1

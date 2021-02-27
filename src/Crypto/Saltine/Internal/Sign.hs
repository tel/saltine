{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.Sign
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.Sign (
    sign
  , signPK
  , signSK
  , c_sign_keypair
  , c_sign
  , c_sign_open
  , c_sign_detached
  , c_sign_verify_detached
) where

import Foreign.C
import Foreign.Ptr

sign, signPK, signSK :: Int

-- Signatures
-- | The maximum size of a signature prepended to a message to form a
-- signed message.
sign   = fromIntegral c_crypto_sign_bytes
-- | The size of a public key for signing verification
signPK = fromIntegral c_crypto_sign_publickeybytes
-- | The size of a secret key for signing
signSK = fromIntegral c_crypto_sign_secretkeybytes

-- src/libsodium/crypto_sign/crypto_sign.c
foreign import ccall "crypto_sign_bytes"
  c_crypto_sign_bytes :: CSize
foreign import ccall "crypto_sign_publickeybytes"
  c_crypto_sign_publickeybytes :: CSize
foreign import ccall "crypto_sign_secretkeybytes"
  c_crypto_sign_secretkeybytes :: CSize


foreign import ccall "crypto_sign_keypair"
  c_sign_keypair :: Ptr CChar
                 -- ^ Public key output buffer
                 -> Ptr CChar
                 -- ^ Secret key output buffer
                 -> IO CInt
                 -- ^ Always 0

foreign import ccall "crypto_sign"
  c_sign :: Ptr CChar
         -- ^ Signed message output buffer
         -> Ptr CULLong
         -- ^ Length of signed message
         -> Ptr CChar
         -- ^ Constant message buffer
         -> CULLong
         -- ^ Length of message input buffer
         -> Ptr CChar
         -- ^ Constant secret key buffer
         -> IO CInt
         -- ^ Always 0

foreign import ccall "crypto_sign_open"
  c_sign_open :: Ptr CChar
              -- ^ Message output buffer
              -> Ptr CULLong
              -- ^ Length of message
              -> Ptr CChar
              -- ^ Constant signed message buffer
              -> CULLong
              -- ^ Length of signed message buffer
              -> Ptr CChar
              -- ^ Public key buffer
              -> IO CInt
              -- ^ 0 if signature is verifiable, -1 otherwise

foreign import ccall "crypto_sign_detached"
    c_sign_detached :: Ptr CChar
                    -- ^ Signature output buffer
                    -> Ptr CULLong
                    -- ^ Length of the signature
                    -> Ptr CChar
                    -- ^ Constant message buffer
                    -> CULLong
                    -- ^ Length of message buffer
                    -> Ptr CChar
                    -- ^ Constant secret key buffer
                    -> IO CInt
foreign import ccall "crypto_sign_verify_detached"
    c_sign_verify_detached :: Ptr CChar
                           -- ^ Signature buffer
                           -> Ptr CChar
                           -- ^ Constant signed message buffer
                           -> CULLong
                           -- ^ Length of signed message buffer
                           -> Ptr CChar
                           -- ^ Public key buffer
                           -> IO CInt

{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.Stream
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.Stream (
    streamKey
  , streamNonce
  , c_stream
  , c_stream_xor
) where

import Foreign.C
import Foreign.Ptr

streamKey, streamNonce :: Int

-- Streams
-- | The size of a key for the cryptographic stream generation
streamKey   = fromIntegral c_crypto_stream_keybytes
-- | The size of a nonce for the cryptographic stream generation
streamNonce = fromIntegral c_crypto_stream_noncebytes

-- src/libsodium/crypto_stream/crypto_stream.c
-- src/libsodium/include/sodium/crypto_stream.h
foreign import ccall "crypto_stream_keybytes"
  c_crypto_stream_keybytes :: CSize
foreign import ccall "crypto_stream_noncebytes"
  c_crypto_stream_noncebytes :: CSize


foreign import ccall "crypto_stream"
  c_stream :: Ptr CChar
           -- ^ Stream output buffer
           -> CULLong
           -- ^ Length of stream to generate
           -> Ptr CChar
           -- ^ Constant nonce buffer
           -> Ptr CChar
           -- ^ Constant key buffer
           -> IO CInt
           -- ^ Always 0

foreign import ccall "crypto_stream_xor"
  c_stream_xor :: Ptr CChar
               -- ^ Ciphertext output buffer
               -> Ptr CChar
               -- ^ Constant message buffer
               -> CULLong
               -- ^ Length of message buffer
               -> Ptr CChar
               -- ^ Constant nonce buffer
               -> Ptr CChar
               -- ^ Constant key buffer
               -> IO CInt
               -- ^ Always 0

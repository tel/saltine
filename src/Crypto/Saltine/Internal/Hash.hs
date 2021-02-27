{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.Hash
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.Hash (
    hash
  , shorthash
  , shorthashKey
  , generichashOutLenMax
  , generichashKeyLenMax
  , c_hash
  , c_shorthash
  , c_generichash
) where

import Foreign.C
import Foreign.Ptr

hash, shorthash, shorthashKey, generichashOutLenMax, generichashKeyLenMax :: Int

-- Hashes
-- | The size of a hash resulting from
-- 'Crypto.Saltine.Internal.Hash.hash'.
hash         = fromIntegral c_crypto_hash_bytes
-- | The size of a keyed hash resulting from
-- 'Crypto.Saltine.Internal.Hash.shorthash'.
shorthash    = fromIntegral c_crypto_shorthash_bytes
-- | The size of a hashing key for the keyed hash function
-- 'Crypto.Saltine.Internal.Hash.shorthash'.
shorthashKey = fromIntegral c_crypto_shorthash_keybytes
-- | The maximum output size of the generic hash function
-- 'Crypto.Saltine.Core.Hash.generichash'
generichashOutLenMax = fromIntegral c_crypto_generichash_bytes_max
-- | The maximum key size of the generic hash function
-- 'Crypto.Saltine.Core.Hash.generichash'
generichashKeyLenMax = fromIntegral c_crypto_generichash_keybytes_max

-- src/libsodium/crypto_generichash/crypto_generichash.c
foreign import ccall "crypto_generichash_bytes_max"
  c_crypto_generichash_bytes_max :: CSize
foreign import ccall "crypto_generichash_keybytes_max"
  c_crypto_generichash_keybytes_max :: CSize

-- src/libsodium/crypto_hash/crypto_hash.c
-- src/libsodium/include/sodium/crypto_hash.h
foreign import ccall "crypto_hash_bytes"
  c_crypto_hash_bytes :: CSize

-- src/libsodium/crypto_shorthash/crypto_shorthash.c
-- src/libsodium/include/sodium/crypto_shorthash.h
foreign import ccall "crypto_shorthash_bytes"
  c_crypto_shorthash_bytes :: CSize
foreign import ccall "crypto_shorthash_keybytes"
  c_crypto_shorthash_keybytes :: CSize


foreign import ccall "crypto_hash"
  c_hash :: Ptr CChar
         -- ^ Output hash buffer
         -> Ptr CChar
         -- ^ Constant message buffer
         -> CULLong
         -- ^ Constant message buffer length
         -> IO CInt
         -- ^ Always 0

foreign import ccall "crypto_shorthash"
  c_shorthash :: Ptr CChar
              -- ^ Output hash buffer
              -> Ptr CChar
              -- ^ Constant message buffer
              -> CULLong
              -- ^ Message buffer length
              -> Ptr CChar
              -- ^ Constant Key buffer
              -> IO CInt
              -- ^ Always 0

foreign import ccall "crypto_generichash"
  c_generichash :: Ptr CChar
                -- ^ Output hash buffer
                -> CULLong
                -- ^ Output hash length
                -> Ptr CChar
                -- ^ Constant message buffer
                -> CULLong
                -- ^ Message buffer length
                -> Ptr CChar
                -- ^ Constant Key buffer
                -> CULLong
                -- ^ Key buffer length
                -> IO CInt
                -- ^ Always 0

{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, DeriveGeneric, ForeignFunctionInterface #-}
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
    hash_bytes
  , shorthash_bytes
  , shorthash_keybytes
  , generichash_bytes_max
  , generichash_keybytes_max
  , c_hash
  , c_shorthash
  , c_generichash
  , nullShKey
  , shorthash
  , ShorthashKey(..)
  , GenerichashKey(..)
  , GenerichashOutLen(..)
) where

import Control.DeepSeq
import Crypto.Saltine.Class
import Crypto.Saltine.Internal.Util as U
import Data.ByteString              (ByteString)
import Data.Data                    (Data, Typeable)
import Data.Hashable                (Hashable)
import Data.Monoid
import Foreign.C
import Foreign.Ptr
import GHC.Generics                 (Generic)

import qualified Data.ByteString       as S
import qualified Data.ByteString.Char8 as S8

-- | An opaque 'shorthash' cryptographic secret key.
newtype ShorthashKey = ShK ByteString deriving (Ord, Hashable, Data, Typeable, Generic, NFData)
instance Eq ShorthashKey where
    ShK a == ShK b = U.compare a b
instance Show ShorthashKey where
    show k = "Hash.ShorthashKey {hashesTo = \"" <> (bin2hex . shorthash nullShKey $ encode k) <> "}\""

-- | Used for our `Show` instances
nullShKey :: ShorthashKey
nullShKey = ShK (S8.replicate shorthash_keybytes '\NUL')

-- | Computes a very short, fast keyed hash.
-- This function is defined here to break circulat module imports
shorthash :: ShorthashKey
          -> ByteString
          -- ^ Message
          -> ByteString
          -- ^ Hash
shorthash (ShK k) m = snd . buildUnsafeByteString shorthash_bytes $ \ph ->
  constByteStrings [k, m] $ \[(pk, _), (pm, _)] ->
    c_shorthash ph pm (fromIntegral $ S.length m) pk

instance IsEncoding ShorthashKey where
  decode v = if S.length v == shorthash_keybytes
           then Just (ShK v)
           else Nothing
  {-# INLINE decode #-}
  encode (ShK v) = v
  {-# INLINE encode #-}

-- | An opaque 'generichash' cryptographic secret key.
newtype GenerichashKey = GhK ByteString deriving (Ord, Hashable, Data, Typeable, Generic, NFData)
instance Eq GenerichashKey where
    GhK a == GhK b = U.compare a b
instance Show GenerichashKey where
    show k = "Hash.GenerichashKey {hashesTo = \"" <> (bin2hex . shorthash nullShKey $ encode k) <> "}\""

instance IsEncoding GenerichashKey where
  decode v = if S.length v <= generichash_keybytes_max
             then Just (GhK v)
             else Nothing
  {-# INLINE decode #-}
  encode (GhK v) = v
  {-# INLINE encode #-}

newtype GenerichashOutLen = GhOL Int deriving (Eq, Ord, Hashable, Data, Typeable, Generic, NFData)

hash_bytes, shorthash_bytes, shorthash_keybytes, generichash_bytes_max, generichash_keybytes_max :: Int

-- Hashes
-- | The size of a hash resulting from
-- 'Crypto.Saltine.Internal.Hash.hash'.
hash_bytes         = fromIntegral c_crypto_hash_bytes
-- | The size of a keyed hash resulting from
-- 'Crypto.Saltine.Internal.Hash.shorthash'.
shorthash_bytes    = fromIntegral c_crypto_shorthash_bytes
-- | The size of a hashing key for the keyed hash function
-- 'Crypto.Saltine.Internal.Hash.shorthash'.
shorthash_keybytes = fromIntegral c_crypto_shorthash_keybytes
-- | The maximum output size of the generic hash function
-- 'Crypto.Saltine.Core.Hash.generichash'
generichash_bytes_max = fromIntegral c_crypto_generichash_bytes_max
-- | The maximum key size of the generic hash function
-- 'Crypto.Saltine.Core.Hash.generichash'
generichash_keybytes_max = fromIntegral c_crypto_generichash_keybytes_max

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

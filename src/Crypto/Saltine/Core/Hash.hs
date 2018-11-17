{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, DeriveGeneric #-}

 -- |
-- Module      : Crypto.Saltine.Core.Hash
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Hashing: "Crypto.Saltine.Core.Hash"
--
-- The 'hash' function hashes a message 'ByteString' and returns a
-- hash. Hashes are always of length 'Bytes.hash'. The 'shorthash'
-- function hashes a message 'ByteString' with respect to a secret key
-- and returns a very short hash. Short hashes are always of length
-- 'Bytes.shorthash'.
--
-- The 'hash' function is designed to be usable as a strong component
-- of DSA, RSA-PSS, key derivation, hash-based message-authentication
-- codes, hash-based ciphers, and various other common
-- applications. "Strong" means that the security of these
-- applications, when instantiated with 'hash', is the same as the
-- security of the applications against generic attacks. In
-- particular, the 'hash' function is designed to make finding
-- collisions difficult.
--
-- 'hash' is currently an implementation of SHA-512. 'shorthash' is
-- currently an implementation of SipHash-2-4
-- (<https://131002.net/siphash/>).
--
-- There has been considerable degradation of public confidence in the
-- security conjectures for many hash functions, including
-- SHA-512. However, for the moment, there do not appear to be
-- alternatives that inspire satisfactory levels of confidence. One
-- can hope that NIST's SHA-3 competition will improve the situation.
--
-- Sodium includes an implementation of the Blake2 hash
-- (<https://blake2.net/>) but since this is not standard NaCl nor was
-- Blake2 selected to be SHA-3 the library doesn't bind it.
--
-- This is version 2010.08.30 of the hash.html web page. Information
-- about SipHash has been added.
module Crypto.Saltine.Core.Hash (
  ShorthashKey,
  hash,
  shorthash, newShorthashKey
  ) where

import           Crypto.Saltine.Class
import           Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import           Control.Applicative
import           Foreign.C
import           Foreign.Ptr
import qualified Data.ByteString as S
import           Data.ByteString (ByteString)
import           Data.Hashable (Hashable)
import           Data.Data (Data, Typeable)
import           GHC.Generics (Generic)

-- | Computes a cryptographically collision-resistant hash making
-- @hash m == hash m' ==> m == m'@ highly likely even when under
-- attack.
hash :: ByteString
     -- ^ Message
     -> ByteString
     -- ^ Hash
hash m = snd . buildUnsafeByteString Bytes.hash $ \ph ->
  constByteStrings [m] $ \[(pm, _)] -> c_hash ph pm (fromIntegral $ S.length m)

-- | An opaque 'shorthash' cryptographic secret key.
newtype ShorthashKey = ShK ByteString deriving (Eq, Ord, Hashable, Data, Typeable, Generic)

instance IsEncoding ShorthashKey where
  decode v = if S.length v == Bytes.shorthashKey
           then Just (ShK v)
           else Nothing
  {-# INLINE decode #-}
  encode (ShK v) = v
  {-# INLINE encode #-}

-- | Randomly generates a new key for 'shorthash'.
newShorthashKey :: IO ShorthashKey
newShorthashKey = ShK <$> randomByteString Bytes.shorthashKey

-- | Computes a very short, fast keyed hash.
shorthash :: ShorthashKey
          -> ByteString
          -- ^ Message
          -> ByteString
          -- ^ Hash
shorthash (ShK k) m = snd . buildUnsafeByteString Bytes.shorthash $ \ph ->
  constByteStrings [k, m] $ \[(pk, _), (pm, _)] ->
    c_shorthash ph pm (fromIntegral $ S.length m) pk

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

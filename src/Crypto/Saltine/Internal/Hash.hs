-- |
-- Module      : Crypto.Saltine.Internal.Hash
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
-- 
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Hashing: "Crypto.Saltine.Internal.Hash"
-- 
-- The 'hash' function hashes a message 'V.Vector' and returns a
-- hash. Hashes are always of length 'Bytes.hash'. The 'shorthash'
-- function hashes a message 'V.Vector' with respect to a secret key
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
module Crypto.Saltine.Internal.Hash (
  ShorthashKey,
  hash,
  shorthash, newShorthashKey
  ) where

import Crypto.Saltine.Class
import Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import Foreign.C
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Foreign.Storable
import System.IO.Unsafe
import Data.Word
import qualified Data.Vector.Storable as V

import Control.Applicative

hash :: V.Vector Word8
        -- ^ Message
        -> V.Vector Word8
        -- ^ Hash
hash m = snd . buildUnsafeCVector Bytes.hash $ \ph ->
  constVectors [m] $ \[pm] -> c_hash ph pm (fromIntegral $ V.length m)

-- | An opaque 'shorthash' cryptographic secret key.
newtype ShorthashKey = ShK (V.Vector Word8) deriving (Eq, Ord)

instance IsEncoding ShorthashKey where
  decode v = case V.length v == Bytes.shorthashKey of
    True -> Just (ShK v)
    False -> Nothing
  {-# INLINE decode #-}
  encode (ShK v) = v
  {-# INLINE encode #-}

newShorthashKey :: IO ShorthashKey
newShorthashKey = ShK <$> randomVector Bytes.shorthashKey

shorthash :: ShorthashKey
             -> V.Vector Word8
             -- ^ Message
             -> V.Vector Word8
             -- ^ Hash
shorthash (ShK k) m = snd . buildUnsafeCVector Bytes.shorthash $ \ph ->
  constVectors [k, m] $ \[pk, pm] ->
  c_shorthash ph pm (fromIntegral $ V.length m) pk
             
foreign import ccall "crypto_hash"
  c_hash :: Ptr Word8
            -- ^ Output hash buffer
            -> Ptr Word8
            -- ^ Constant message buffer
            -> CULLong
            -- ^ Constant message buffer length
            -> IO CInt
            -- ^ Always 0

foreign import ccall "crypto_shorthash"
  c_shorthash :: Ptr Word8
                 -- ^ Output hash buffer
                 -> Ptr Word8
                 -- ^ Constant message buffer
                 -> CULLong
                 -- ^ Message buffer length
                 -> Ptr Word8
                 -- ^ Constant Key buffer
                 -> IO CInt
                 -- ^ Always 0

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
-- Sodium includes an implementation of the Blake2b hash function
-- (<https://blake2.net/>) and is bound here as the 'generichash'
-- function.
--
-- This is version 2010.08.30 of the hash.html web page. Information
-- about SipHash has been added.
module Crypto.Saltine.Core.Hash (
  ShorthashKey,
  hash,
  shorthash, newShorthashKey,
  GenerichashKey,
  newGenerichashKey,
  GenerichashOutLen,
  generichashOutLen, generichash
  ) where

import Control.Applicative
import Crypto.Saltine.Internal.Hash
            ( c_hash
            , c_shorthash
            , c_generichash
            , shorthash
            , ShorthashKey(..)
            , GenerichashKey(..)
            , GenerichashOutLen(..)
            )
import Crypto.Saltine.Internal.Util as U
import Data.ByteString              (ByteString)

import qualified Crypto.Saltine.Internal.Hash as Bytes
import qualified Data.ByteString              as S

-- | Computes a cryptographically collision-resistant hash making
-- @hash m == hash m' ==> m == m'@ highly likely even when under
-- attack.
hash :: ByteString
     -- ^ Message
     -> ByteString
     -- ^ Hash
hash m = snd . buildUnsafeByteString Bytes.hash_bytes $ \ph ->
  constByteStrings [m] $ \[(pm, _)] -> c_hash ph pm (fromIntegral $ S.length m)

-- | Randomly generates a new key for 'shorthash'.
newShorthashKey :: IO ShorthashKey
newShorthashKey = ShK <$> randomByteString Bytes.shorthash_keybytes

-- | Randomly generates a new key for 'generichash' of the given length.
newGenerichashKey :: Int -> IO (Maybe GenerichashKey)
newGenerichashKey n = if n >= 0 && n <= Bytes.generichash_keybytes_max
                      then Just . GhK <$> randomByteString n
                      else return Nothing

-- | Create a validated Generichash output length
generichashOutLen :: Int -> Maybe GenerichashOutLen
generichashOutLen n = if n > 0 && n <= Bytes.generichash_bytes_max
                      then Just $ GhOL $ fromIntegral n
                      else Nothing

-- | Computes a generic, keyed hash.
generichash :: GenerichashKey
            -> ByteString
            -- ^ Message
            -> GenerichashOutLen
            -- ^ Desired output hash length
            -> ByteString
            -- ^ Hash
generichash (GhK k) m (GhOL outLen) = snd . buildUnsafeByteString outLen $ \ph ->
  constByteStrings [k, m] $ \[(pk, _), (pm, _)] ->
    c_generichash ph (fromIntegral outLen) pm (fromIntegral $ S.length m) pk (fromIntegral $ S.length k)

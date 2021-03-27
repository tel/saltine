{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, DeriveGeneric, ForeignFunctionInterface #-}
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
    stream_keybytes
  , stream_noncebytes
  , c_stream
  , c_stream_xor
  , Key(..)
  , Nonce(..)
) where

import Control.DeepSeq              (NFData)
import Crypto.Saltine.Class
import Crypto.Saltine.Core.Hash     (shorthash)
import Crypto.Saltine.Internal.Hash (nullShKey)
import Crypto.Saltine.Internal.Util as U
import Data.ByteString              (ByteString)
import Data.Data                    (Data, Typeable)
import Data.Hashable                (Hashable)
import Foreign.C
import Foreign.Ptr
import GHC.Generics                 (Generic)

import qualified Data.ByteString as S

-- | An opaque 'stream' cryptographic key.
newtype Key = Key ByteString deriving (Ord, Hashable, Data, Typeable, Generic, NFData)
instance Eq Key where
    Key a == Key b = U.compare a b
instance Show Key where
    show k = "Stream.Key {hashesTo = \"" <> (bin2hex . shorthash nullShKey $ encode k) <> "}\""

instance IsEncoding Key where
  decode v = if S.length v == stream_keybytes
           then Just (Key v)
           else Nothing
  {-# INLINE decode #-}
  encode (Key v) = v
  {-# INLINE encode #-}

-- | An opaque 'stream' nonce.
newtype Nonce = Nonce ByteString deriving (Eq, Ord, Hashable, Data, Typeable, Generic, NFData)
instance Show Nonce where
    show k = "Stream.Nonce " <> bin2hex (encode k)

instance IsNonce Nonce where
  zero = Nonce (S.replicate stream_noncebytes 0)
  nudge (Nonce n) = Nonce (nudgeBS n)

instance IsEncoding Nonce where
  decode v = if S.length v == stream_noncebytes
           then Just (Nonce v)
           else Nothing
  {-# INLINE decode #-}
  encode (Nonce v) = v
  {-# INLINE encode #-}

stream_keybytes, stream_noncebytes :: Int

-- Streams
-- | The size of a key for the cryptographic stream generation
stream_keybytes   = fromIntegral c_crypto_stream_keybytes
-- | The size of a nonce for the cryptographic stream generation
stream_noncebytes = fromIntegral c_crypto_stream_noncebytes

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

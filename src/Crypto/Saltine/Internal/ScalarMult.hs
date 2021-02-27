{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, DeriveGeneric, ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.ScalarMult
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.ScalarMult (
    mult
  , multScalar
  , c_scalarmult
  , c_scalarmult_base
  , GroupElement(..)
  , Scalar(..)
) where

import Control.DeepSeq
import Crypto.Saltine.Class
import Data.ByteString (ByteString)
import Data.Data       (Data, Typeable)
import Data.Hashable   (Hashable)
import Foreign.C
import Foreign.Ptr
import GHC.Generics    (Generic)

import qualified Data.ByteString as S


-- | A group element.
newtype GroupElement = GE ByteString deriving (Eq, Ord, Hashable, Data, Typeable, Generic, NFData)

-- | A scalar integer.
newtype Scalar       = Sc ByteString deriving (Eq, Ord, Hashable, Data, Typeable, Generic, NFData)

instance IsEncoding GroupElement where
  decode v = if S.length v == mult
           then Just (GE v)
           else Nothing
  {-# INLINE decode #-}
  encode (GE v) = v
  {-# INLINE encode #-}

instance IsEncoding Scalar where
  decode v = if S.length v == multScalar
           then Just (Sc v)
           else Nothing
  {-# INLINE decode #-}
  encode (Sc v) = v
  {-# INLINE encode #-}


mult, multScalar :: Int

-- ScalarMult
-- | Size of a group element string representation for
-- @crypto_scalarmult@.
mult = fromIntegral c_crypto_scalarmult_bytes
-- | Size of a integer string representation for @crypto_scalarmult@.
multScalar = fromIntegral c_crypto_scalarmult_scalarbytes

-- src/libsodium/crypto_scalarmult/crypto_scalarmult.c
foreign import ccall "crypto_scalarmult_bytes"
  c_crypto_scalarmult_bytes :: CSize
foreign import ccall "crypto_scalarmult_scalarbytes"
  c_crypto_scalarmult_scalarbytes :: CSize

foreign import ccall "crypto_scalarmult"
  c_scalarmult :: Ptr CChar
               -- ^ Output group element buffer
               -> Ptr CChar
               -- ^ Input integer buffer
               -> Ptr CChar
               -- ^ Input group element buffer
               -> IO CInt
               -- ^ Always 0

foreign import ccall "crypto_scalarmult_base"
  c_scalarmult_base :: Ptr CChar
                    -- ^ Output group element buffer
                    -> Ptr CChar
                    -- ^ Input integer buffer
                    -> IO CInt
                    -- ^ Always 0

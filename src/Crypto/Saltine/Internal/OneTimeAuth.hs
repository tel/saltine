{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, DeriveGeneric, ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.OneTimeAuth
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.OneTimeAuth (
    onetime
  , onetimeKey
  , c_onetimeauth
  , c_onetimeauth_verify
  , Key(..)
  , Authenticator(..)
) where


import Control.DeepSeq
import Crypto.Saltine.Class
import Crypto.Saltine.Internal.Util as U
import Data.ByteString              (ByteString)
import Data.Data                    (Data, Typeable)
import Data.Hashable                (Hashable)
import Foreign.C
import Foreign.Ptr
import GHC.Generics                 (Generic)

import qualified Data.ByteString as S

-- | An opaque 'auth' cryptographic key.
newtype Key           = Key ByteString deriving (Ord, Hashable, Data, Typeable, Generic, NFData)
instance Eq Key where
    Key a == Key b = U.compare a b

-- | An opaque 'auth' authenticator.
newtype Authenticator = Au ByteString  deriving (Eq, Ord, Hashable, Data, Typeable, Generic, NFData)

instance IsEncoding Key where
  decode v = if S.length v == onetimeKey
           then Just (Key v)
           else Nothing
  {-# INLINE decode #-}
  encode (Key v) = v
  {-# INLINE encode #-}

instance IsEncoding Authenticator where
  decode v = if S.length v == onetime
           then Just (Au v)
           else Nothing
  {-# INLINE decode #-}
  encode (Au v) = v
  {-# INLINE encode #-}


onetime, onetimeKey :: Int

-- OneTimeAuth
-- | Size of a @crypto_onetimeauth@ authenticator.
onetime    = fromIntegral c_crypto_onetimeauth_bytes
-- | Size of a @crypto_onetimeauth@ authenticator key.
onetimeKey = fromIntegral c_crypto_onetimeauth_keybytes

-- src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c
foreign import ccall "crypto_onetimeauth_bytes"
  c_crypto_onetimeauth_bytes :: CSize
foreign import ccall "crypto_onetimeauth_keybytes"
  c_crypto_onetimeauth_keybytes :: CSize


foreign import ccall "crypto_onetimeauth"
  c_onetimeauth :: Ptr CChar
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
foreign import ccall "crypto_onetimeauth_verify"
  c_onetimeauth_verify :: Ptr CChar
                       -- ^ Constant authenticator buffer
                       -> Ptr CChar
                       -- ^ Constant message buffer
                       -> CULLong
                       -- ^ Length of message buffer
                       -> Ptr CChar
                       -- ^ Constant key buffer
                       -> CInt
                       -- ^ Success if 0, failure if -1

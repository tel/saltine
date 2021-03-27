{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, DeriveGeneric, ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.Auth
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.Auth (
    auth_bytes
  , auth_keybytes
  , c_auth
  , c_auth_verify
  , Key(..)
  , Authenticator(..)
) where


import Control.DeepSeq
import Crypto.Saltine.Class
import Crypto.Saltine.Core.Hash     (shorthash)
import Crypto.Saltine.Internal.Hash (nullShKey)
import Crypto.Saltine.Internal.Util as U
import Data.ByteString              (ByteString)
import Data.Data                    (Data, Typeable)
import Data.Hashable                (Hashable)
import GHC.Generics                 (Generic)
import Foreign.C
import Foreign.Ptr

import qualified Data.ByteString as S

-- | An opaque 'auth' cryptographic key.
newtype Key = Key ByteString deriving (Ord, Hashable, Data, Typeable, Generic, NFData)
instance Eq Key where
    Key a == Key b = U.compare a b
instance Show Key where
    show k = "Auth.Key {hashesTo = \"" <> (bin2hex . shorthash nullShKey $ encode k) <> "}\""

instance IsEncoding Key where
  decode v = if S.length v == auth_keybytes
           then Just (Key v)
           else Nothing
  {-# INLINE decode #-}
  encode (Key v) = v
  {-# INLINE encode #-}

-- | An opaque 'auth' authenticator.
newtype Authenticator = Au ByteString deriving (Eq, Ord, Hashable, Data, Typeable, Generic, NFData)
instance Show Authenticator where
    show k = "Auth.Authenticator " <> bin2hex (encode k)

instance IsEncoding Authenticator where
  decode v = if S.length v == auth_bytes
           then Just (Au v)
           else Nothing
  {-# INLINE decode #-}
  encode (Au v) = v
  {-# INLINE encode #-}


auth_bytes, auth_keybytes :: Int

-- Authentication
-- | Size of a @crypto_auth@ authenticator.
auth_bytes    = fromIntegral c_crypto_auth_bytes
-- | Size of a @crypto_auth@ authenticator key.
auth_keybytes = fromIntegral c_crypto_auth_keybytes

-- src/libsodium/crypto_auth/crypto_auth.c
foreign import ccall "crypto_auth_bytes"
  c_crypto_auth_bytes :: CSize
foreign import ccall "crypto_auth_keybytes"
  c_crypto_auth_keybytes :: CSize

foreign import ccall "crypto_auth"
  c_auth :: Ptr CChar
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
foreign import ccall "crypto_auth_verify"
  c_auth_verify :: Ptr CChar
                -- ^ Constant authenticator buffer
                -> Ptr CChar
                -- ^ Constant message buffer
                -> CULLong
                -- ^ Length of message buffer
                -> Ptr CChar
                -- ^ Constant key buffer
                -> CInt
                -- ^ Success if 0, failure if -1

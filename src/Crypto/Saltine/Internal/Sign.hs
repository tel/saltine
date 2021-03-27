{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, DeriveGeneric, ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.Sign
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.Sign (
    sign_bytes
  , sign_publickeybytes
  , sign_secretkeybytes
  , c_sign_keypair
  , c_sign
  , c_sign_open
  , c_sign_detached
  , c_sign_verify_detached
  , SecretKey(..)
  , PublicKey(..)
  , Keypair
) where

import Control.DeepSeq              (NFData)
import Crypto.Saltine.Class
import Crypto.Saltine.Core.Hash     (shorthash)
import Crypto.Saltine.Internal.Hash (nullShKey)
import Crypto.Saltine.Internal.Util as U
import Data.ByteString              (ByteString)
import Data.Data                    (Data, Typeable)
import Data.Hashable                (Hashable)
import Data.Monoid
import Foreign.C
import Foreign.Ptr
import GHC.Generics                 (Generic)

import qualified Data.ByteString as S


-- | An opaque 'box' cryptographic secret key.
newtype SecretKey = SK ByteString deriving (Ord, Hashable, Data, Typeable, Generic, NFData)
instance Eq SecretKey where
    SK a == SK b = U.compare a b
instance Show SecretKey where
    show k = "Sign.SecretKey {hashesTo = \"" <> (bin2hex . shorthash nullShKey $ encode k) <> "}\""

instance IsEncoding SecretKey where
  decode v = if S.length v == sign_secretkeybytes
           then Just (SK v)
           else Nothing
  {-# INLINE decode #-}
  encode (SK v) = v
  {-# INLINE encode #-}

-- | An opaque 'box' cryptographic public key.
newtype PublicKey = PK ByteString deriving (Ord, Data, Typeable, Hashable, Generic, NFData)
instance Eq PublicKey where
    PK a == PK b = U.compare a b
instance Show PublicKey where
    show k = "Sign.PublicKey {hashesTo = \"" <> (bin2hex . shorthash nullShKey $ encode k) <> "}\""

instance IsEncoding PublicKey where
  decode v = if S.length v == sign_publickeybytes
           then Just (PK v)
           else Nothing
  {-# INLINE decode #-}
  encode (PK v) = v
  {-# INLINE encode #-}

-- | A convenience type for keypairs
type Keypair = (SecretKey, PublicKey)

sign_bytes, sign_publickeybytes, sign_secretkeybytes :: Int

-- Signatures
-- | The maximum size of a signature prepended to a message to form a
-- signed message.
sign_bytes          = fromIntegral c_crypto_sign_bytes
-- | The size of a public key for signing verification
sign_publickeybytes = fromIntegral c_crypto_sign_publickeybytes
-- | The size of a secret key for signing
sign_secretkeybytes = fromIntegral c_crypto_sign_secretkeybytes

-- src/libsodium/crypto_sign/crypto_sign.c
foreign import ccall "crypto_sign_bytes"
  c_crypto_sign_bytes :: CSize
foreign import ccall "crypto_sign_publickeybytes"
  c_crypto_sign_publickeybytes :: CSize
foreign import ccall "crypto_sign_secretkeybytes"
  c_crypto_sign_secretkeybytes :: CSize


foreign import ccall "crypto_sign_keypair"
  c_sign_keypair :: Ptr CChar
                 -- ^ Public key output buffer
                 -> Ptr CChar
                 -- ^ Secret key output buffer
                 -> IO CInt
                 -- ^ Always 0

foreign import ccall "crypto_sign"
  c_sign :: Ptr CChar
         -- ^ Signed message output buffer
         -> Ptr CULLong
         -- ^ Length of signed message
         -> Ptr CChar
         -- ^ Constant message buffer
         -> CULLong
         -- ^ Length of message input buffer
         -> Ptr CChar
         -- ^ Constant secret key buffer
         -> IO CInt
         -- ^ Always 0

foreign import ccall "crypto_sign_open"
  c_sign_open :: Ptr CChar
              -- ^ Message output buffer
              -> Ptr CULLong
              -- ^ Length of message
              -> Ptr CChar
              -- ^ Constant signed message buffer
              -> CULLong
              -- ^ Length of signed message buffer
              -> Ptr CChar
              -- ^ Public key buffer
              -> IO CInt
              -- ^ 0 if signature is verifiable, -1 otherwise

foreign import ccall "crypto_sign_detached"
    c_sign_detached :: Ptr CChar
                    -- ^ Signature output buffer
                    -> Ptr CULLong
                    -- ^ Length of the signature
                    -> Ptr CChar
                    -- ^ Constant message buffer
                    -> CULLong
                    -- ^ Length of message buffer
                    -> Ptr CChar
                    -- ^ Constant secret key buffer
                    -> IO CInt
foreign import ccall "crypto_sign_verify_detached"
    c_sign_verify_detached :: Ptr CChar
                           -- ^ Signature buffer
                           -> Ptr CChar
                           -- ^ Constant signed message buffer
                           -> CULLong
                           -- ^ Length of signed message buffer
                           -> Ptr CChar
                           -- ^ Public key buffer
                           -> IO CInt

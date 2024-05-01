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
  , c_sign_ed25519_pk_to_curve25519
  , c_sign_ed25519_sk_to_curve25519
  , SecretKey(..)
  , PublicKey(..)
  , Keypair(..)
  , Signature(..)
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
newtype SecretKey = SK { unSK :: ByteString } deriving (Ord, Hashable, Data, Typeable, Generic, NFData)
instance Eq SecretKey where
    SK a == SK b = U.compare a b
instance Show SecretKey where
    show k = "Sign.SecretKey {hashesTo = \"" <> (bin2hex . shorthash nullShKey $ encode k) <> "\"}"

instance IsEncoding SecretKey where
  decode v = if S.length v == sign_secretkeybytes
           then Just (SK v)
           else Nothing
  {-# INLINE decode #-}
  encode (SK v) = v
  {-# INLINE encode #-}

-- | An opaque 'box' cryptographic public key.
newtype PublicKey = PK { unPK :: ByteString } deriving (Ord, Data, Typeable, Hashable, Generic, NFData)
instance Eq PublicKey where
    PK a == PK b = U.compare a b
instance Show PublicKey where
    show k = "Sign.PublicKey {hashesTo = \"" <> (bin2hex . shorthash nullShKey $ encode k) <> "\"}"

instance IsEncoding PublicKey where
  decode v = if S.length v == sign_publickeybytes
           then Just (PK v)
           else Nothing
  {-# INLINE decode #-}
  encode (PK v) = v
  {-# INLINE encode #-}

-- | A convenience type for keypairs
data Keypair = Keypair {
    secretKey :: SecretKey
  , publicKey :: PublicKey
} deriving (Ord, Data, Typeable, Generic)

instance Eq Keypair where
    kp1 == kp2 = U.compare (encode $ secretKey kp1) (encode $ secretKey kp2)
            !&&! U.compare (encode $ publicKey kp1) (encode $ publicKey kp2)

instance Show Keypair where
    show k = "Sign.Keypair {secretKey = " <> show (secretKey k) <> ", publicKey = " <> show (publicKey k) <> "}"

instance Hashable Keypair
instance NFData   Keypair


-- | A signature for a Message
newtype Signature = Signature { unSignature :: ByteString } deriving (Ord, Data, Typeable, Hashable, Generic, NFData)
instance Eq Signature where
    Signature a == Signature b = U.compare a b
instance Show Signature where
    show k = "Sign.Signature " <> bin2hex (encode k)

-- | Actual signatures may be shorter, but not when generated with saltine.
instance IsEncoding Signature where
  decode v = if S.length v == sign_bytes
           then Just (Signature v)
           else Nothing
  {-# INLINE decode #-}
  encode (Signature s) = s
  {-# INLINE encode #-}

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

foreign import ccall "crypto_sign_ed25519_pk_to_curve25519"
    c_sign_ed25519_pk_to_curve25519 :: Ptr CChar
                                    -- ^ X25519 public key output buffer
                                    -> Ptr CChar
                                    -- ^ Ed25519 public key buffer
                                    -> IO CInt

foreign import ccall "crypto_sign_ed25519_sk_to_curve25519"
    c_sign_ed25519_sk_to_curve25519 :: Ptr CChar
                                    -- ^ X25519 secret key output buffer
                                    -> Ptr CChar
                                    -- ^ Ed25519 secret key buffer
                                    -> IO CInt

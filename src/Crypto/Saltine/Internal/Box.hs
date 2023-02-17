{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, DeriveGeneric, ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.Box
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.Box (
    box_publickeybytes
  , box_secretkeybytes
  , box_noncebytes
  , box_zerobytes
  , box_boxzerobytes
  , box_macbytes
  , box_beforenmbytes
  , box_sealbytes
  , c_box_keypair
  , c_box_easy
  , c_box_open_easy
  , c_box_beforenm
  , c_box_easy_afternm
  , c_box_open_easy_afternm
  , c_box_seal
  , c_box_seal_open
  , SecretKey(..)
  , PublicKey(..)
  , Keypair(..)
  , CombinedKey(..)
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
    show k = "Box.SecretKey {hashesTo = \"" <> (bin2hex . shorthash nullShKey $ encode k) <> "\"}"

instance IsEncoding SecretKey where
  decode v = if S.length v == box_secretkeybytes
           then Just (SK v)
           else Nothing
  {-# INLINE decode #-}
  encode (SK v) = v
  {-# INLINE encode #-}

-- | An opaque 'box' cryptographic public key.
newtype PublicKey = PK { unPK :: ByteString } deriving (Ord, Hashable, Data, Typeable, Generic, NFData)
instance Eq PublicKey where
    PK a == PK b = U.compare a b
instance Show PublicKey where
    show k = "Box.PublicKey {hashesTo = \"" <> (bin2hex . shorthash nullShKey $ encode k) <> "\"}"

instance IsEncoding PublicKey where
  decode v = if S.length v == box_publickeybytes
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
    show k = "Box.Keypair {secretKey = " <> show (secretKey k) <> ", publicKey = " <> show (publicKey k) <> "}"

instance Hashable Keypair
instance NFData   Keypair

-- | An opaque 'boxAfterNM' cryptographic combined key.
newtype CombinedKey = CK { unCK :: ByteString } deriving (Ord, Hashable, Data, Typeable, Generic, NFData)
instance Eq CombinedKey where
    CK a == CK b = U.compare a b
instance Show CombinedKey where
    show k = "Box.CombinedKey {hashesTo = \"" <> (bin2hex . shorthash nullShKey $ encode k) <> "\"}"

instance IsEncoding CombinedKey where
  decode v = if S.length v == box_beforenmbytes
           then Just (CK v)
           else Nothing
  {-# INLINE decode #-}
  encode (CK v) = v
  {-# INLINE encode #-}

-- | An opaque 'box' nonce.
newtype Nonce = Nonce { unNonce :: ByteString } deriving (Eq, Ord, Hashable, Data, Typeable, Generic, NFData)
instance Show Nonce where
    show k = "Box.Nonce " <> bin2hex (encode k)

instance IsEncoding Nonce where
  decode v = if S.length v == box_noncebytes
           then Just (Nonce v)
           else Nothing
  {-# INLINE decode #-}
  encode (Nonce v) = v
  {-# INLINE encode #-}

instance IsNonce Nonce where
  zero            = Nonce (S.replicate box_noncebytes 0)
  nudge (Nonce n) = Nonce (nudgeBS n)


box_publickeybytes, box_secretkeybytes, box_noncebytes, box_zerobytes, box_boxzerobytes :: Int
box_macbytes, box_beforenmbytes, box_sealbytes :: Int

-- Box
-- | Size of a @crypto_box@ public key
box_publickeybytes  = fromIntegral c_crypto_box_publickeybytes
-- | Size of a @crypto_box@ secret key
box_secretkeybytes  = fromIntegral c_crypto_box_secretkeybytes
-- | Size of a @crypto_box@ nonce
box_noncebytes      = fromIntegral c_crypto_box_noncebytes
-- | Size of 0-padding prepended to messages before using @crypto_box@
-- or after using @crypto_box_open@
box_zerobytes       = fromIntegral c_crypto_box_zerobytes
-- | Size of 0-padding prepended to ciphertext before using
-- @crypto_box_open@ or after using @crypto_box@.
box_boxzerobytes    = fromIntegral c_crypto_box_boxzerobytes
box_macbytes        = fromIntegral c_crypto_box_macbytes
-- | Size of a @crypto_box_beforenm@-generated combined key
box_beforenmbytes   = fromIntegral c_crypto_box_beforenmbytes

-- SealedBox
-- | Amount by which ciphertext is longer than plaintext
-- in sealed boxes
box_sealbytes       = fromIntegral c_crypto_box_sealbytes

-- src/libsodium/crypto_box/crypto_box.c
foreign import ccall "crypto_box_publickeybytes"
  c_crypto_box_publickeybytes :: CSize
foreign import ccall "crypto_box_secretkeybytes"
  c_crypto_box_secretkeybytes :: CSize
foreign import ccall "crypto_box_beforenmbytes"
  c_crypto_box_beforenmbytes :: CSize
foreign import ccall "crypto_box_noncebytes"
  c_crypto_box_noncebytes :: CSize
foreign import ccall "crypto_box_zerobytes"
  c_crypto_box_zerobytes :: CSize
foreign import ccall "crypto_box_boxzerobytes"
  c_crypto_box_boxzerobytes :: CSize
foreign import ccall "crypto_box_macbytes"
  c_crypto_box_macbytes :: CSize

-- src/libsodium/crypto_box_seal.c
foreign import ccall "crypto_box_sealbytes"
  c_crypto_box_sealbytes :: CSize

-- | Should always return a 0.
foreign import ccall "crypto_box_keypair"
  c_box_keypair :: Ptr CChar
                -- ^ Public key
                -> Ptr CChar
                -- ^ Secret key
                -> IO CInt
                -- ^ Always 0

-- | The secretbox C API uses C strings.
foreign import ccall "crypto_box_easy"
  c_box_easy :: Ptr CChar
             -- ^ Cipher output buffer
             -> Ptr CChar
             -- ^ Constant message input buffer
             -> CULLong
             -- ^ Length of message input buffer
             -> Ptr CChar
             -- ^ Constant nonce buffer
             -> Ptr CChar
             -- ^ Constant public key buffer
             -> Ptr CChar
             -- ^ Constant secret key buffer
             -> IO CInt
             -- ^ Always 0

-- | The secretbox C API uses C strings.
foreign import ccall "crypto_box_open_easy"
  c_box_open_easy :: Ptr CChar
                  -- ^ Message output buffer
                  -> Ptr CChar
                  -- ^ Constant ciphertext input buffer
                  -> CULLong
                  -- ^ Length of message input buffer
                  -> Ptr CChar
                  -- ^ Constant nonce buffer
                  -> Ptr CChar
                  -- ^ Constant public key buffer
                  -> Ptr CChar
                  -- ^ Constant secret key buffer
                  -> IO CInt
                  -- ^ 0 for success, -1 for failure to verify

-- | Single target key precompilation.
foreign import ccall "crypto_box_beforenm"
  c_box_beforenm :: Ptr CChar
                 -- ^ Combined key output buffer
                 -> Ptr CChar
                 -- ^ Constant public key buffer
                 -> Ptr CChar
                 -- ^ Constant secret key buffer
                 -> IO CInt
                 -- ^ Always 0

-- | Precompiled key crypto box. Uses C strings.
foreign import ccall "crypto_box_easy_afternm"
  c_box_easy_afternm :: Ptr CChar
                     -- ^ Cipher output buffer
                     -> Ptr CChar
                     -- ^ Constant message input buffer
                     -> CULLong
                     -- ^ Length of message input buffer (incl. 0s)
                     -> Ptr CChar
                     -- ^ Constant nonce buffer
                     -> Ptr CChar
                     -- ^ Constant combined key buffer
                     -> IO CInt
                     -- ^ Always 0

-- | The secretbox C API uses C strings.
foreign import ccall "crypto_box_open_easy_afternm"
  c_box_open_easy_afternm :: Ptr CChar
                          -- ^ Message output buffer
                          -> Ptr CChar
                          -- ^ Constant ciphertext input buffer
                          -> CULLong
                          -- ^ Length of message input buffer (incl. 0s)
                          -> Ptr CChar
                          -- ^ Constant nonce buffer
                          -> Ptr CChar
                          -- ^ Constant combined key buffer
                          -> IO CInt
                          -- ^ 0 for success, -1 for failure to verify


-- | The sealedbox C API uses C strings.
foreign import ccall "crypto_box_seal"
  c_box_seal :: Ptr CChar
             -- ^ Cipher output buffer
             -> Ptr CChar
             -- ^ Constant message input buffer
             -> CULLong
             -- ^ Length of message input buffer
             -> Ptr CChar
             -- ^ Constant public key buffer
             -> IO CInt
             -- ^ Always 0

-- | The sealedbox C API uses C strings.
foreign import ccall "crypto_box_seal_open"
  c_box_seal_open :: Ptr CChar
                  -- ^ Message output buffer
                  -> Ptr CChar
                  -- ^ Constant ciphertext input buffer
                  -> CULLong
                  -- ^ Length of message input buffer
                  -> Ptr CChar
                  -- ^ Constant public key buffer
                  -> Ptr CChar
                  -- ^ Constant secret key buffer
                  -> IO CInt
                  -- ^ 0 for success, -1 for failure to decrypt

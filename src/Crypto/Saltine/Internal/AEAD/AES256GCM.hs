{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, DeriveGeneric, ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.AEAD.AES256GCM
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.AEAD.AES256GCM (
    aead_aes256gcm_keybytes
  , aead_aes256gcm_npubbytes
  , aead_aes256gcm_abytes
  , c_aead_aes256gcm_is_available
  , c_aead
  , c_aead_open
  , c_aead_detached
  , c_aead_open_detached
  , Key(..)
  , Nonce(..)
) where

import Control.DeepSeq
import Crypto.Saltine.Class
import Crypto.Saltine.Core.Hash     (shorthash)
import Crypto.Saltine.Internal.Hash (nullShKey)
import Crypto.Saltine.Internal.Util as U
import Data.ByteString              (ByteString)
import Data.Data                    (Data, Typeable)
import Data.Hashable                (Hashable)
import Data.Monoid
import GHC.Generics                 (Generic)
import Foreign.C
import Foreign.Ptr

import qualified Data.ByteString as S

-- | An opaque 'AES256GCM' cryptographic key.
newtype Key = Key { unKey :: ByteString } deriving (Ord, Hashable, Data, Typeable, Generic, NFData)
instance Eq Key where
    Key a == Key b = U.compare a b
instance Show Key where
    show k = "AEAD.AES256GCM.Key {hashesTo = \"" <> (bin2hex . shorthash nullShKey $ encode k) <> "}\""

instance IsEncoding Key where
  decode v = if S.length v == aead_aes256gcm_keybytes
           then Just (Key v)
           else Nothing
  {-# INLINE decode #-}
  encode (Key v) = v
  {-# INLINE encode #-}

-- | An opaque 'AES256GCM' nonce.
newtype Nonce = Nonce { unNonce :: ByteString } deriving (Eq, Ord, Hashable, Data, Typeable, Generic, NFData)
instance Show Nonce where
    show k = "AEAD.AES256GCM.Nonce " <> bin2hex (encode k)

instance IsEncoding Nonce where
  decode v = if S.length v == aead_aes256gcm_npubbytes
           then Just (Nonce v)
           else Nothing
  {-# INLINE decode #-}
  encode (Nonce v) = v
  {-# INLINE encode #-}

instance IsNonce Nonce where
  zero            = Nonce (S.replicate aead_aes256gcm_npubbytes 0)
  nudge (Nonce n) = Nonce (nudgeBS n)


aead_aes256gcm_keybytes, aead_aes256gcm_abytes, aead_aes256gcm_npubbytes :: Int

-- | Size of an AES256 key
aead_aes256gcm_keybytes  = fromIntegral c_crypto_aead_aes256gcm_keybytes
-- | Size of an AES256 nonce
aead_aes256gcm_npubbytes = fromIntegral c_crypto_aead_aes256gcm_npubbytes
-- | Size of an AES256 authentication tag
aead_aes256gcm_abytes    = fromIntegral c_crypto_aead_aes256gcm_abytes


-- src/libsodium/crypto_aead/aes256gcm/sodium/aead_aes256gcm.c
-- src/libsodium/include/sodium/crypto_aead_aes256gcm.h
foreign import ccall "crypto_aead_aes256gcm_keybytes"
    c_crypto_aead_aes256gcm_keybytes :: CSize
foreign import ccall "crypto_aead_aes256gcm_npubbytes"
    c_crypto_aead_aes256gcm_npubbytes:: CSize
foreign import ccall "crypto_aead_aes256gcm_abytes"
    c_crypto_aead_aes256gcm_abytes :: CSize


foreign import ccall "crypto_aead_aes256gcm_is_available"
  c_aead_aes256gcm_is_available
    :: IO CInt

-- | The aead C API uses C strings. Always returns 0.
foreign import ccall "crypto_aead_aes256gcm_encrypt"
  c_aead
    :: Ptr CChar
    -- ^ Cipher output buffer
    -> Ptr CULLong
    -- ^ Cipher output bytes used
    -> Ptr CChar
    -- ^ Constant message input buffer
    -> CULLong
    -- ^ Length of message input buffer
    -> Ptr CChar
    -- ^ Constant aad input buffer
    -> CULLong
    -- ^ Length of aad input buffer
    -> Ptr CChar
    -- ^ Unused 'nsec' value (must be NULL)
    -> Ptr CChar
    -- ^ Constant nonce buffer
    -> Ptr CChar
    -- ^ Constant key buffer
    -> IO CInt

-- | The aead open C API uses C strings. Returns 0 if successful.
foreign import ccall "crypto_aead_aes256gcm_decrypt"
  c_aead_open
    :: Ptr CChar
    -- ^ Message output buffer
    -> Ptr CULLong
    -- ^ Message output bytes used
    -> Ptr CChar
    -- ^ Unused 'nsec' value (must be NULL)
    -> Ptr CChar
    -- ^ Constant ciphertext input buffer
    -> CULLong
    -- ^ Length of ciphertext input buffer
    -> Ptr CChar
    -- ^ Constant aad input buffer
    -> CULLong
    -- ^ Length of aad input buffer
    -> Ptr CChar
    -- ^ Constant nonce buffer
    -> Ptr CChar
    -- ^ Constant key buffer
    -> IO CInt

-- | The aead C API uses C strings. Always returns 0.
foreign import ccall "crypto_aead_aes256gcm_encrypt_detached"
  c_aead_detached
    :: Ptr CChar
    -- ^ Cipher output buffer
    -> Ptr CChar
    -- ^ Tag output buffer
    -> Ptr CULLong
    -- ^ Tag bytes used
    -> Ptr CChar
    -- ^ Constant message input buffer
    -> CULLong
    -- ^ Length of message input buffer
    -> Ptr CChar
    -- ^ Constant aad input buffer
    -> CULLong
    -- ^ Length of aad input buffer
    -> Ptr CChar
    -- ^ Unused 'nsec' value (must be NULL)
    -> Ptr CChar
    -- ^ Constant nonce buffer
    -> Ptr CChar
    -- ^ Constant key buffer
    -> IO CInt

-- | The aead open C API uses C strings. Returns 0 if successful.
foreign import ccall "crypto_aead_aes256gcm_decrypt_detached"
  c_aead_open_detached
    :: Ptr CChar
    -- ^ Message output buffer
    -> Ptr CChar
    -- ^ Unused 'nsec' value (must be NULL)
    -> Ptr CChar
    -- ^ Constant ciphertext input buffer
    -> CULLong
    -- ^ Length of ciphertext input buffer
    -> Ptr CChar
    -- ^ Constant tag input buffer
    -> Ptr CChar
    -- ^ Constant aad input buffer
    -> CULLong
    -- ^ Length of aad input buffer
    -> Ptr CChar
    -- ^ Constant nonce buffer
    -> Ptr CChar
    -- ^ Constant key buffer
    -> IO CInt

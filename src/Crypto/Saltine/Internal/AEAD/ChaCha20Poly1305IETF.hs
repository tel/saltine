{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, DeriveGeneric, ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.AEAD.ChaCha20Poly1305IETF
-- Copyright   : (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.AEAD.ChaCha20Poly1305IETF (
    aead_chacha20poly1305_ietf_keybytes
  , aead_chacha20poly1305_ietf_npubbytes
  , aead_chacha20poly1305_ietf_abytes
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
import Foreign.C
import Foreign.Ptr
import GHC.Generics                 (Generic)

import qualified Data.ByteString as S


-- | An opaque 'ChaCha20Poly1305IETF' cryptographic key.
newtype Key = Key { unKey :: ByteString } deriving (Ord, Hashable, Data, Typeable, Generic, NFData)
instance Eq Key where
    Key a == Key b = U.compare a b
instance Show Key where
    show k = "AEAD.ChaCha20Poly1305IETF.Key {hashesTo = \"" <> (bin2hex . shorthash nullShKey $ encode k) <> "}\""

instance IsEncoding Key where
  decode v = if S.length v == aead_chacha20poly1305_ietf_keybytes
           then Just (Key v)
           else Nothing
  {-# INLINE decode #-}
  encode (Key v) = v
  {-# INLINE encode #-}

-- | An opaque 'ChaCha20Poly1305IETF' nonce.
newtype Nonce = Nonce { unNonce :: ByteString } deriving (Eq, Ord, Hashable, Data, Typeable, Generic, NFData)
instance Show Nonce where
    show k = "AEAD.ChaCha20Poly1305IETF.Nonce " <> bin2hex (encode k)

instance IsEncoding Nonce where
  decode v = if S.length v == aead_chacha20poly1305_ietf_npubbytes
           then Just (Nonce v)
           else Nothing
  {-# INLINE decode #-}
  encode (Nonce v) = v
  {-# INLINE encode #-}

instance IsNonce Nonce where
  zero            = Nonce (S.replicate aead_chacha20poly1305_ietf_npubbytes 0)
  nudge (Nonce n) = Nonce (nudgeBS n)

aead_chacha20poly1305_ietf_keybytes, aead_chacha20poly1305_ietf_abytes, aead_chacha20poly1305_ietf_npubbytes :: Int

-- | Size of a ChaCha20-Poly1305-IETF key
aead_chacha20poly1305_ietf_keybytes  = fromIntegral c_crypto_aead_chacha20poly1305_ietf_keybytes
-- | Size of a ChaCha20-Poly1305-IETF nonce
aead_chacha20poly1305_ietf_npubbytes = fromIntegral c_crypto_aead_chacha20poly1305_ietf_npubbytes
-- | Size of a ChaCha20-Poly1305-IETF authentication tag
aead_chacha20poly1305_ietf_abytes    = fromIntegral c_crypto_aead_chacha20poly1305_ietf_abytes


-- src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c
-- src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h
foreign import ccall "crypto_aead_chacha20poly1305_ietf_keybytes"
    c_crypto_aead_chacha20poly1305_ietf_keybytes :: CSize
foreign import ccall "crypto_aead_chacha20poly1305_ietf_npubbytes"
    c_crypto_aead_chacha20poly1305_ietf_npubbytes:: CSize
foreign import ccall "crypto_aead_chacha20poly1305_ietf_abytes"
    c_crypto_aead_chacha20poly1305_ietf_abytes :: CSize


-- | The aead C API uses C strings. Always returns 0.
foreign import ccall "crypto_aead_chacha20poly1305_ietf_encrypt"
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
foreign import ccall "crypto_aead_chacha20poly1305_ietf_decrypt"
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
foreign import ccall "crypto_aead_chacha20poly1305_ietf_encrypt_detached"
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
foreign import ccall "crypto_aead_chacha20poly1305_ietf_decrypt_detached"
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

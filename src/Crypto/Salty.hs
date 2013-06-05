{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE MagicHash #-}

module Crypto.Salty where

import Foreign.C
import Foreign.Ptr
import Foreign.ForeignPtr
import System.IO.Unsafe

import qualified Data.Vector.Storable as V
import qualified Data.Vector.Storable.Mutable as VM

import Data.Data
import Data.Word
import Data.Monoid
import qualified Data.ByteString as S
import Control.Exception
import Control.Applicative

import qualified Crypto.Salty.ByteSizes as Bytes

{- Notes:

* Check thread safety of `randombytes_random`, `randombytes_uniform`,
  `randombytes_buf`, `randombytes_close`, `crypto_sign_keypair`, and
  `crypto_box_keypair`.

* Consider a monadic interface for using the `randombytes_*` interface
  so as to ensure `close` is called and that it is used in a threadsafe
  manner.

* Keys are insecurely read from disk---they may be copied and then
  paged back to disk. Use at your own risk.

-}

{- Todo:

* Refactor secretbox/secretboxOpen

-}

data SaltyException = OptimizationFailure | UnknownFailure
                    deriving (Typeable, Show)
instance Exception SaltyException

foreign import ccall "sodium_init" c_sodiumInit :: IO CInt

-- | Runs Sodiums's optimizer. This has no semantic effect, but both
-- may boost the speed of Sodium after running it. It is recommended
-- in production environments. It is, however, NOT thread-safe so no
-- other Sodium functions should be called until it successfully
-- returns.
optimize :: IO ()
optimize = do
  err <- c_sodiumInit
  case err of
    0  -> -- everything went well
      return ()
    1  -> -- already initialized, we're good
      return ()
    -1 -> -- some kind of failure
      throw OptimizationFailure
    _  -> -- what?
      throw UnknownFailure

-- Random Things

foreign import ccall "randombytes_buf"
  c_randombytes_buf :: Ptr Word8 -> CInt -> IO ()

randomVector :: Int -> IO (V.Vector Word8)
randomVector n = do fp <- mallocForeignPtrArray n
                    withForeignPtr fp (`c_randombytes_buf` fromIntegral n)
                    V.unsafeFreeze $ VM.unsafeFromForeignPtr fp 0 n


-- SecretBox

newSecretBoxNonce :: IO (V.Vector Word8)
newSecretBoxNonce = randomVector Bytes.secretBoxNonce

newSecretBoxKey :: IO (V.Vector Word8)
newSecretBoxKey = randomVector Bytes.secretBoxKey

-- | The secretbox C API uses 0-padded C strings
foreign import ccall "crypto_secretbox"
  c_secretbox :: Ptr Word8 ->
                 -- ^ Cipher 0-padded output buffer
                 Ptr Word8 ->
                 -- ^ Constant 0-padded message input buffer
                 CInt ->
                 -- ^ Length of message input buffer (incl. 0s)
                 Ptr Word8 ->
                 -- ^ Constant nonce buffer
                 Ptr Word8 ->
                 -- ^ Constant key buffer
                 IO ()

-- | The secretbox C API uses 0-padded C strings
foreign import ccall "crypto_secretbox_open"
  c_secretbox_open :: Ptr Word8 ->
                      -- ^ Message 0-padded output buffer
                      Ptr Word8 ->
                      -- ^ Constant 0-padded message input buffer
                      CInt ->
                      -- ^ Length of message input buffer (incl. 0s)
                      Ptr Word8 ->
                      -- ^ Constant nonce buffer
                      Ptr Word8 ->
                      -- ^ Constant key buffer
                      IO CInt

-- | The secretbox function is designed to meet the standard notions
-- of privacy and authenticity for a secret-key
-- authenticated-encryption scheme using nonces. It implements
-- `crypto_secretbox_xsalsa20poly1305`, a particular combination of
-- Salsa20 and Poly1305 specified in "Cryptography in NaCl".
secretbox :: V.Vector Word8 ->
             -- ^ Key
             V.Vector Word8 ->
             -- ^ Nonce
             V.Vector Word8 ->
             -- ^ Message
             V.Vector Word8
             -- ^ Ciphertext
secretbox key nonce msg = unsafePerformIO $ do
  cipherfp <- mallocForeignPtrArray paddedMsgLen
  withForeignPtr cipherfp $ \pcipher -> do
    V.unsafeWith key $ \pkey -> do
      V.unsafeWith paddedMsg $ \pmsg -> do
        V.unsafeWith nonce $ \pnonce -> do
          c_secretbox pcipher pmsg (fromIntegral paddedMsgLen) pnonce pkey
  V.drop Bytes.secretBoxBoxZero
    <$> V.unsafeFreeze (VM.unsafeFromForeignPtr cipherfp 0 paddedMsgLen)
  where
    paddedMsg = V.replicate Bytes.secretBoxZero 0 <> msg
    paddedMsgLen = V.length paddedMsg

-- | If validation fails, returns 'Nothing'.
secretboxOpen :: V.Vector Word8 ->
                 -- ^ Key
                 V.Vector Word8 ->
                 -- ^ Nonce
                 V.Vector Word8 ->
                 -- ^ Ciphertext
                 Maybe (V.Vector Word8)
                 -- ^ Message
secretboxOpen key nonce cipher = unsafePerformIO $ do
  messagefp <- mallocForeignPtrArray paddedCipherLen
  err <- withForeignPtr messagefp $ \pmsg -> do
    V.unsafeWith key $ \pkey -> do
      V.unsafeWith paddedCipher $ \pcipher -> do
        V.unsafeWith nonce $ \pnonce -> do
          c_secretbox_open pmsg pcipher (fromIntegral paddedCipherLen) pnonce pkey
  case err of
    0  -> Just . V.drop Bytes.secretBoxZero
          <$> V.unsafeFreeze (VM.unsafeFromForeignPtr messagefp 0 paddedCipherLen)
    -1 -> return Nothing
    n  -> error ("secretboxOpen: unexpected error code " ++ show n)
  where
    paddedCipher = V.replicate Bytes.secretBoxBoxZero 0 <> cipher
    paddedCipherLen = V.length paddedCipher
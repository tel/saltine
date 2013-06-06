-- |
-- Module      : Crypto.Saltine.Internal.OneTimeAuth
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
-- 
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Secret-key single-message authentication:
-- "Crypto.Saltine.Internal.OneTimeAuth"
-- 
-- The 'auth' function authenticates a message 'V.Vector' using a
-- secret key The function returns an authenticator. The 'verify'
-- function checks if it's passed a correct authenticator of a message
-- under the given secret key.
-- 
-- The 'auth' function, viewed as a function of the message for a
-- uniform random key, is designed to meet the standard notion of
-- unforgeability after a single message. After the sender
-- authenticates one message, an attacker cannot find authenticators
-- for any other messages.
-- 
-- The sender must not use 'auth' to authenticate more than one
-- message under the same key. Authenticators for two messages under
-- the same key should be expected to reveal enough information to
-- allow forgeries of authenticators on other messages.
-- 
-- "Crypto.Saltine.Internal.OneTimeAuth" is
-- @crypto_onetimeauth_poly1305@, an authenticator specified in
-- "Cryptography in NaCl" (<http://nacl.cr.yp.to/valid.html>), Section
-- 9. This authenticator is proven to meet the standard notion of
-- unforgeability after a single message.
-- 
-- This is version 2010.08.30 of the onetimeauth.html web page.

module Crypto.Saltine.Internal.OneTimeAuth (
  newKey,
  auth, verify
  ) where

import Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import Foreign.C
import Foreign.Ptr
import Data.Word
import qualified Data.Vector.Storable as V

-- | Creates a random key of the correct size for 'auth' and 'verify'.
newKey :: IO (V.Vector Word8)
newKey = randomVector Bytes.onetimeKey

-- | Executes @crypto_onetimeauth@ on the passed 'V.Vector's. THIS IS
-- MEMORY UNSAFE unless the key and nonce are precisely the right
-- sizes.
auth :: V.Vector Word8
        -- ^ Key
        -> V.Vector Word8
        -- ^ Message
        -> V.Vector Word8
        -- ^ Authenticator
auth key msg =
  snd . buildUnsafeCVector Bytes.onetime $ \pa ->
    constVectors [key, msg] $ \[pk, pm] ->
    c_onetimeauth pa pm (fromIntegral $ V.length msg) pk

-- | Executes @crypto_auth_verify@ on the passed 'V.Vector's. THIS IS
-- MEMORY UNSAFE unless the key and nonce are precisely the right
-- sizes.
verify :: V.Vector Word8
          -- ^ Key
          -> V.Vector Word8
          -- ^ Message
          -> V.Vector Word8
          -- ^ Authenticator
          -> Bool
          -- ^ Is this message authentic?
verify key msg a =
  unsafeDidSucceed $ constVectors [key, msg, a] $ \[pk, pm, pa] ->
  return $ c_onetimeauth_verify pa pm (fromIntegral $ V.length msg) pk

foreign import ccall "crypto_onetimeauth"
  c_onetimeauth :: Ptr Word8
                   -- ^ Authenticator output buffer
                   -> Ptr Word8
                   -- ^ Constant message buffer
                   -> CULLong
                   -- ^ Length of message buffer
                   -> Ptr Word8
                   -- ^ Constant key buffer
                   -> IO CInt
                   -- ^ Always 0

-- | We don't even include this in the IO monad since all of the
-- buffers are constant.
foreign import ccall "crypto_onetimeauth_verify"
  c_onetimeauth_verify :: Ptr Word8
                          -- ^ Constant authenticator buffer
                          -> Ptr Word8
                          -- ^ Constant message buffer
                          -> CULLong
                          -- ^ Length of message buffer
                          -> Ptr Word8
                          -- ^ Constant key buffer
                          -> CInt
                          -- ^ Success if 0, failure if -1
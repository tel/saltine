-- |
-- Module      : Crypto.Saltine.Internal.Auth
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
-- 
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Secret-key message authentication: 
-- "Crypto.Saltine.Internal.Auth"
-- 
-- The 'auth' function authenticates a message 'V.Vector' using a
-- secret key The function returns an authenticator. The 'verify'
-- function checks if it's passed a correct authenticator of a message
-- under the given secret key.
-- 
-- The 'auth' function, viewed as a function of the message for a
-- uniform random key, is designed to meet the standard notion of
-- unforgeability. This means that an attacker cannot find
-- authenticators for any messages not authenticated by the sender,
-- even if the attacker has adaptively influenced the messages
-- authenticated by the sender. For a formal definition see, e.g.,
-- Section 2.4 of Bellare, Kilian, and Rogaway, \"The security of the
-- cipher block chaining message authentication code,\" Journal of
-- Computer and System Sciences 61 (2000), 362–399;
-- <http://www-cse.ucsd.edu/~mihir/papers/cbc.html>.
-- 
-- Saltine does not make any promises regarding \"strong\"
-- unforgeability; perhaps one valid authenticator can be converted
-- into another valid authenticator for the same message. NaCl also
-- does not make any promises regarding \"truncated unforgeability.\"
-- 
-- "Crypto.Saltine.Internal.Auth" is currently an implementation of
-- HMAC-SHA-512-256, i.e., the first 256 bits of
-- HMAC-SHA-512. HMAC-SHA-512-256 is conjectured to meet the standard
-- notion of unforgeability.
-- 
-- This is version 2010.08.30 of the auth.html web page.
module Crypto.Saltine.Internal.Auth (
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
newKey = randomVector Bytes.authKey

-- | Executes @crypto_auth@ on the passed 'V.Vector's. THIS IS MEMORY
-- UNSAFE unless the key and nonce are precisely the right sizes.
auth :: V.Vector Word8
          -- ^ Key
          -> V.Vector Word8
          -- ^ Message
          -> V.Vector Word8
          -- ^ Authenticator
auth key msg =
  snd . buildUnsafeCVector Bytes.auth $ \pa ->
    constVectors [key, msg] $ \[pk, pm] ->
    c_auth pa pm (fromIntegral $ V.length msg) pk

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
  return $ c_auth_verify pa pm (fromIntegral $ V.length msg) pk

foreign import ccall "crypto_auth"
  c_auth :: Ptr Word8
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
foreign import ccall "crypto_auth_verify"
  c_auth_verify :: Ptr Word8
                   -- ^ Constant authenticator buffer
                   -> Ptr Word8
                   -- ^ Constant message buffer
                   -> CULLong
                   -- ^ Length of message buffer
                   -> Ptr Word8
                   -- ^ Constant key buffer
                   -> CInt
                   -- ^ Success if 0, failure if -1

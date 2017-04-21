-- |
-- Module      : Crypto.Saltine.Core.OneTimeAuth
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Secret-key single-message authentication:
-- "Crypto.Saltine.Core.OneTimeAuth"
--
-- The 'auth' function authenticates a message 'ByteString' using a
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
-- "Crypto.Saltine.Core.OneTimeAuth" is
-- @crypto_onetimeauth_poly1305@, an authenticator specified in
-- "Cryptography in NaCl" (<http://nacl.cr.yp.to/valid.html>), Section
-- 9. This authenticator is proven to meet the standard notion of
-- unforgeability after a single message.
--
-- This is version 2010.08.30 of the onetimeauth.html web page.
module Crypto.Saltine.Core.OneTimeAuth (
  Key, Authenticator,
  newKey,
  auth, verify
  ) where

import           Crypto.Saltine.Class
import           Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import           Control.Applicative
import           Foreign.C
import           Foreign.Ptr
import qualified Data.ByteString                   as S
import           Data.ByteString                     (ByteString)

-- $types

-- | An opaque 'auth' cryptographic key.
newtype Key           = Key ByteString deriving (Eq, Ord)

-- | An opaque 'auth' authenticator.
newtype Authenticator = Au ByteString  deriving (Eq, Ord)

instance IsEncoding Key where
  decode v = if S.length v == Bytes.onetimeKey
           then Just (Key v)
           else Nothing
  {-# INLINE decode #-}
  encode (Key v) = v
  {-# INLINE encode #-}

instance IsEncoding Authenticator where
  decode v = if S.length v == Bytes.onetime
           then Just (Au v)
           else Nothing
  {-# INLINE decode #-}
  encode (Au v) = v
  {-# INLINE encode #-}

-- | Creates a random key of the correct size for 'auth' and 'verify'.
newKey :: IO Key
newKey = Key <$> randomVector Bytes.onetimeKey

-- | Builds a keyed 'Authenticator' for a message. This
-- 'Authenticator' is /impossible/ to forge so long as the 'Key' is
-- never used twice.
auth :: Key
     -> ByteString
     -- ^ Message
     -> Authenticator
auth (Key key) msg =
  Au . snd . buildUnsafeCVector Bytes.onetime $ \pa ->
    constVectors [key, msg] $ \[(pk, _), (pm, _)] ->
      c_onetimeauth pa pm (fromIntegral $ S.length msg) pk

-- | Verifies that an 'Authenticator' matches a given message and key.
verify :: Key
       -> Authenticator
       -> ByteString
       -- ^ Message
       -> Bool
       -- ^ Is this message authentic?
verify (Key key) (Au a) msg =
  unsafeDidSucceed $ constVectors [key, msg, a] $ \
    [(pk, _), (pm, _), (pa, _)] ->
      return $ c_onetimeauth_verify pa pm (fromIntegral $ S.length msg) pk

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

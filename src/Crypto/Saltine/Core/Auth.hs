-- |
-- Module      : Crypto.Saltine.Core.Auth
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Secret-key message authentication:
-- "Crypto.Saltine.Core.Auth"
--
-- The 'auth' function authenticates a message 'ByteString' using a
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
-- "Crypto.Saltine.Core.Auth" is currently an implementation of
-- HMAC-SHA-512-256, i.e., the first 256 bits of
-- HMAC-SHA-512. HMAC-SHA-512-256 is conjectured to meet the standard
-- notion of unforgeability.
--
-- This is version 2010.08.30 of the auth.html web page.
module Crypto.Saltine.Core.Auth (
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
  decode v = if S.length v == Bytes.authKey
           then Just (Key v)
           else Nothing
  {-# INLINE decode #-}
  encode (Key v) = v
  {-# INLINE encode #-}

instance IsEncoding Authenticator where
  decode v = if S.length v == Bytes.auth
           then Just (Au v)
           else Nothing
  {-# INLINE decode #-}
  encode (Au v) = v
  {-# INLINE encode #-}

-- | Creates a random key of the correct size for 'auth' and 'verify'.
newKey :: IO Key
newKey = Key <$> randomByteString Bytes.authKey

-- | Computes an keyed authenticator 'ByteString' from a message. It
-- is infeasible to forge these authenticators without the key, even
-- if an attacker observes many authenticators and messages and has
-- the ability to influence the messages sent.
auth :: Key
     -> ByteString
     -- ^ Message
     -> Authenticator
auth (Key key) msg =
  Au . snd . buildUnsafeByteString Bytes.auth $ \pa ->
    constByteStrings [key, msg] $ \[(pk, _), (pm, mlen)] ->
    c_auth pa pm (fromIntegral mlen) pk

-- | Checks to see if an authenticator is a correct proof that a
-- message was signed by some key.
verify :: Key
       -> Authenticator
       -> ByteString
       -- ^ Message
       -> Bool
       -- ^ Is this message authentic?
verify (Key key) (Au a) msg =
  unsafeDidSucceed $ constByteStrings [key, msg, a] $ \[(pk, _), (pm, mlen), (pa, _)] ->
    return $ c_auth_verify pa pm (fromIntegral mlen) pk

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

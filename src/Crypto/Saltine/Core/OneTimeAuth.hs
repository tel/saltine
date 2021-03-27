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

import Crypto.Saltine.Internal.OneTimeAuth
            ( c_onetimeauth
            , c_onetimeauth_verify
            , Key(..)
            , Authenticator(..)
            )
import Crypto.Saltine.Internal.Util as U
import Data.ByteString              (ByteString)

import qualified Crypto.Saltine.Internal.OneTimeAuth as Bytes
import qualified Data.ByteString                   as S

-- | Creates a random key of the correct size for 'auth' and 'verify'.
newKey :: IO Key
newKey = Key <$> randomByteString Bytes.onetimeauth_keybytes

-- | Builds a keyed 'Authenticator' for a message. This
-- 'Authenticator' is /impossible/ to forge so long as the 'Key' is
-- never used twice.
auth :: Key
     -> ByteString
     -- ^ Message
     -> Authenticator
auth (Key key) msg =
  Au . snd . buildUnsafeByteString Bytes.onetimeauth_bytes $ \pa ->
    constByteStrings [key, msg] $ \[(pk, _), (pm, _)] ->
      c_onetimeauth pa pm (fromIntegral $ S.length msg) pk

-- | Verifies that an 'Authenticator' matches a given message and key.
verify :: Key
       -> Authenticator
       -> ByteString
       -- ^ Message
       -> Bool
       -- ^ Is this message authentic?
verify (Key key) (Au a) msg =
  unsafeDidSucceed $ constByteStrings [key, msg, a] $ \
    [(pk, _), (pm, _), (pa, _)] ->
      return $ c_onetimeauth_verify pa pm (fromIntegral $ S.length msg) pk

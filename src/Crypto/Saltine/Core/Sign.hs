-- |
-- Module      : Crypto.Saltine.Core.Sign
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
-- 
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Signatures: "Crypto.Saltine.Core.Sign"
-- 
-- The 'newKeypair' function randomly generates a secret key and a
-- corresponding public key. The 'sign' function signs a message
-- 'ByteString' using the signer's secret key and returns the
-- resulting signed message. The 'signOpen' function verifies the
-- signature in a signed message using the signer's public key then
-- returns the message without its signature.
-- 
-- "Crypto.Saltine.Core.Sign" is an EdDSA signature using
-- elliptic-curve Curve25519 (see: <http://ed25519.cr.yp.to/>). See
-- also, \"Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter
-- Schwabe, Bo-Yin Yang. High-speed high-security signatures. Journal
-- of Cryptographic Engineering 2 (2012), 77–89.\"
-- <http://ed25519.cr.yp.to/ed25519-20110926.pdf>.
--
-- This is current information as of 2013 June 6.

module Crypto.Saltine.Core.Sign (
  SecretKey, PublicKey, Keypair,
  newKeypair,
  sign, signOpen
  ) where

import Crypto.Saltine.Class
import Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import Foreign.C
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Foreign.Storable
import System.IO.Unsafe
import qualified Data.ByteString as S
import           Data.ByteString (ByteString)

-- $types

-- | An opaque 'box' cryptographic secret key.
newtype SecretKey = SK ByteString deriving (Eq, Ord)

instance IsEncoding SecretKey where
  decode v = case S.length v == Bytes.signSK of
    True -> Just (SK v)
    False -> Nothing
  {-# INLINE decode #-}
  encode (SK v) = v
  {-# INLINE encode #-}

-- | An opaque 'box' cryptographic public key.
newtype PublicKey = PK ByteString deriving (Eq, Ord)

instance IsEncoding PublicKey where
  decode v = case S.length v == Bytes.signPK of
    True -> Just (PK v)
    False -> Nothing
  {-# INLINE decode #-}
  encode (PK v) = v
  {-# INLINE encode #-}

-- | A convenience type for keypairs
type Keypair = (SecretKey, PublicKey)

-- | Creates a random key of the correct size for 'sign' and
-- 'signOpen' of form @(secretKey, publicKey)@.
newKeypair :: IO Keypair
newKeypair = do
  -- This is a little bizarre and a likely source of errors.
  -- _err ought to always be 0.
  ((_err, sk), pk) <- buildUnsafeCVector' Bytes.signPK $ \pkbuf ->
    buildUnsafeCVector' Bytes.signSK $ \skbuf ->
    c_sign_keypair pkbuf skbuf
  return (SK sk, PK pk)

-- | Augments a message with a signature forming a \"signed
-- message\".
sign :: SecretKey
        -> ByteString
        -- ^ Message
        -> ByteString
        -- ^ Signed message
sign (SK k) m = unsafePerformIO $ 
  alloca $ \psmlen -> do
    (_err, sm) <- buildUnsafeCVector' (len + Bytes.sign) $ \psmbuf ->
      constVectors [k, m] $ \[(pk, _), (pm, _)] ->
      c_sign psmbuf psmlen pm (fromIntegral len) pk
    smlen <- peek psmlen
    return $ S.take (fromIntegral smlen) sm
  where len = S.length m

-- | Checks a \"signed message\" returning 'Just' the original message
-- iff the signature was generated using the 'SecretKey' corresponding
-- to the given 'PublicKey'. Returns 'Nothing' otherwise.
signOpen :: PublicKey
            -> ByteString
            -- ^ Signed message
            -> Maybe ByteString
            -- ^ Maybe the restored message
signOpen (PK k) sm = unsafePerformIO $
  alloca $ \pmlen -> do
    (err, m) <- buildUnsafeCVector' smlen $ \pmbuf ->
      constVectors [k, sm] $ \[(pk, _), (psm, _)] ->
      c_sign_open pmbuf pmlen psm (fromIntegral smlen) pk
    mlen <- peek pmlen
    case err of
      0 -> return $ Just $ S.take (fromIntegral mlen) m
      _ -> return $ Nothing
  where smlen = S.length sm


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
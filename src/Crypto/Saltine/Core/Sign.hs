
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
  -- * Documentation
  SecretKey, PublicKey, Keypair(..), Signature,
  newKeypair,
  sign, signOpen,
  signDetached, signVerifyDetached,

  -- * Advanced: Ed25519 to Curve25519
  --
  -- | Ed25519 keys can be converted to X25519 keys, so that the same
  -- key pair can be used both for authenticated encryption
  -- ("Crypto.Saltine.Core.Box") and for signatures
  -- ("Crypto.Saltine.Core.Sign").
  signPublicKeyToScalarMult, signSecretKeyToScalarMult
  ) where

import Crypto.Saltine.Internal.Sign
            ( c_sign_keypair
            , c_sign
            , c_sign_open
            , c_sign_detached
            , c_sign_verify_detached
            , c_sign_ed25519_pk_to_curve25519
            , c_sign_ed25519_sk_to_curve25519
            , SecretKey(..)
            , PublicKey(..)
            , Keypair(..)
            , Signature(..)
            )
import Crypto.Saltine.Internal.Util as U
import Data.ByteString              (ByteString)
import Foreign.Marshal.Alloc
import Foreign.Storable
import System.IO.Unsafe

import qualified Crypto.Saltine.Internal.Sign as Bytes
import qualified Crypto.Saltine.Internal.ScalarMult as SM
import qualified Data.ByteString              as S

-- | Creates a random key of the correct size for 'sign' and
-- 'signOpen' of form @(secretKey, publicKey)@.
newKeypair :: IO Keypair
newKeypair = do
  -- This is a little bizarre and a likely source of errors.
  -- _err ought to always be 0.
  ((_err, sk), pk) <- buildUnsafeByteString' Bytes.sign_publickeybytes $ \pkbuf ->
    buildUnsafeByteString' Bytes.sign_secretkeybytes $ \skbuf ->
      c_sign_keypair pkbuf skbuf
  return $ Keypair (SK sk) (PK pk)

-- | Augments a message with a signature forming a \"signed
-- message\".
sign :: SecretKey
     -> ByteString
     -- ^ Message
     -> ByteString
     -- ^ Signed message
sign (SK k) m = unsafePerformIO $
  alloca $ \psmlen -> do
    (_err, sm) <- buildUnsafeByteString' (len + Bytes.sign_bytes) $ \psmbuf ->
      constByteStrings [k, m] $ \[(pk, _), (pm, _)] ->
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
    (err, m) <- buildUnsafeByteString' smlen $ \pmbuf ->
      constByteStrings [k, sm] $ \[(pk, _), (psm, _)] ->
        c_sign_open pmbuf pmlen psm (fromIntegral smlen) pk
    mlen <- peek pmlen
    case err of
      0 -> return $ Just $ S.take (fromIntegral mlen) m
      _ -> return   Nothing
  where smlen = S.length sm

-- | Returns just the signature for a message using a SecretKey.
signDetached :: SecretKey
             -> ByteString
             -- ^ Message
             -> Signature
             -- ^ Signature
signDetached (SK k) m = unsafePerformIO $
    alloca $ \psmlen -> do
        (_err, sm) <- buildUnsafeByteString' Bytes.sign_bytes $ \sigbuf ->
            constByteStrings [k, m] $ \[(pk, _), (pm, _)] ->
                c_sign_detached sigbuf psmlen pm (fromIntegral len) pk
        smlen <- peek psmlen
        return $ Signature $ S.take (fromIntegral smlen) sm
  where len = S.length m

-- | Returns @True@ if the signature is valid for the given public key and
-- message.
signVerifyDetached :: PublicKey
                   -> Signature
                   -- ^ Signature
                   -> ByteString
                   -- ^ Message (not signed)
                   -> Bool
signVerifyDetached (PK k) (Signature sig) sm = unsafePerformIO $
    constByteStrings [k, sig, sm] $ \[(pk, _), (psig, _), (psm, _)] -> do
        res <- c_sign_verify_detached psig psm (fromIntegral len) pk
        return (res == 0)
  where len = S.length sm

-- | Converts an Ed25519 public key to an X25519 public key.
signPublicKeyToScalarMult :: PublicKey -> Maybe SM.GroupElement
signPublicKeyToScalarMult (PK pk) = unsafePerformIO $ do
  (err,x) <- buildUnsafeByteString' SM.scalarmult_bytes $ \xbuf ->
    constByteStrings [pk] $ \[(edbuf,_)] ->
      c_sign_ed25519_pk_to_curve25519 xbuf edbuf
  case err of
    0 -> return $ Just $ SM.GE x
    _ -> return   Nothing

-- | Converts an Ed25519 secret key to an X25519 secret key.
signSecretKeyToScalarMult :: SecretKey -> Maybe SM.Scalar
signSecretKeyToScalarMult (SK sk) = unsafePerformIO $ do
  (err,x) <- buildUnsafeByteString' SM.scalarmult_bytes $ \xbuf ->
    constByteStrings [sk] $ \[(edbuf,_)] ->
      c_sign_ed25519_sk_to_curve25519 xbuf edbuf
  case err of
    0 -> return $ Just $ SM.Sc x
    _ -> return   Nothing

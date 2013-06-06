-- |
-- Module      : Crypto.Saltine.Internal.Sign
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
-- 
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Signatures: "Crypto.Saltine.Internal.Sign"
-- 
-- The 'newKeypair' function randomly generates a secret key and a
-- corresponding public key. The 'sign' function signs a message
-- 'V.Vector' using the signer's secret key and returns the resulting
-- signed message. The 'signOpen' function verifies the signature in a
-- signed message using the signer's public key then returns the
-- message without its signature.
-- 
-- "Crypto.Saltine.Internal.Sign" is an EdDSA signature using
-- elliptic-curve Curve25519 (see: <http://ed25519.cr.yp.to/>). See
-- also, \"Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter
-- Schwabe, Bo-Yin Yang. High-speed high-security signatures. Journal
-- of Cryptographic Engineering 2 (2012), 77–89.\"
-- <http://ed25519.cr.yp.to/ed25519-20110926.pdf>.
--
-- This is current information as of 2013 June 6.

module Crypto.Saltine.Internal.Sign where

import Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import Foreign.C
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Foreign.Storable
import System.IO.Unsafe
import Data.Word
import qualified Data.Vector.Storable as V

-- | Creates a random key of the correct size for 'sign' and
-- 'signOpen' of form @(secretKey, publicKey)@.
newKeypair :: IO (V.Vector Word8, V.Vector Word8)
newKeypair = do
  -- This is a little bizarre and a likely source of errors.
  -- _err ought to always be 0.
  ((_err, sk), pk) <- buildUnsafeCVector' Bytes.signPK $ \pkbuf ->
    buildUnsafeCVector' Bytes.signSK $ \skbuf ->
    c_sign_keypair pkbuf skbuf
  return (sk, pk)

-- | Executes @crypto_sign@ on the passed 'V.Vector's. THIS IS MEMORY
-- UNSAFE unless the key is precisely the right size.
sign :: V.Vector Word8
        -- ^ Secret key
        -> V.Vector Word8
        -- ^ Message
        -> V.Vector Word8
        -- ^ Signed message
sign k m = unsafePerformIO $ 
  alloca $ \psmlen -> do
    (err, sm) <- buildUnsafeCVector' (len + Bytes.sign) $ \psmbuf ->
      constVectors [k, m] $ \[pk, pm] ->
      c_sign psmbuf psmlen pm (fromIntegral len) pk
    smlen <- peek psmlen
    return $ V.take (fromIntegral smlen) sm
  where len = V.length m

-- | Executes @crypto_sign@ on the passed 'V.Vector's returning 'Just'
-- the original, unsigned message if verification succeeds and
-- 'Nothing' otherwise. THIS IS MEMORY UNSAFE unless the key is
-- precisely the right size.
signOpen :: V.Vector Word8
            -- ^ Public key
            -> V.Vector Word8
            -- ^ Signed message
            -> Maybe (V.Vector Word8)
            -- ^ Maybe the restored message
signOpen k sm = unsafePerformIO $
  alloca $ \pmlen -> do
    (err, m) <- buildUnsafeCVector' smlen $ \pmbuf ->
      constVectors [k, sm] $ \[pk, psm] ->
      c_sign_open pmbuf pmlen psm (fromIntegral smlen) pk
    mlen <- peek pmlen
    case err of
      0 -> return $ Just $ V.take (fromIntegral mlen) m
      _ -> return $ Nothing
  where smlen = V.length sm


foreign import ccall "crypto_sign_keypair"
  c_sign_keypair :: Ptr Word8
                    -- ^ Public key output buffer
                    -> Ptr Word8
                    -- ^ Secret key output buffer
                    -> IO CInt
                    -- ^ Always 0

foreign import ccall "crypto_sign"
  c_sign :: Ptr Word8
            -- ^ Signed message output buffer
            -> Ptr CULLong
            -- ^ Length of signed message
            -> Ptr Word8
            -- ^ Constant message buffer
            -> CULLong
            -- ^ Length of message input buffer
            -> Ptr Word8
            -- ^ Constant secret key buffer
            -> IO CInt
            -- ^ Always 0

foreign import ccall "crypto_sign_open"
  c_sign_open :: Ptr Word8
                 -- ^ Message output buffer
                 -> Ptr CULLong
                 -- ^ Length of message
                 -> Ptr Word8
                 -- ^ Constant signed message buffer
                 -> CULLong
                 -- ^ Length of signed message buffer
                 -> Ptr Word8
                 -- ^ Public key buffer
                 -> IO CInt
                 -- ^ 0 if signature is verifiable, -1 otherwise
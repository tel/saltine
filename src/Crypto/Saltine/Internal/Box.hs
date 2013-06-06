-- |
-- Module      : Crypto.Saltine.Internal.Box
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Secret-key authenticated encryption:
-- "Crypto.Saltine.Internal.Box"
--
-- The 'box' function encrypts and authenticates a message 'V.Vector'
-- using the sender's secret key, the receiver's public key, and a
-- nonce. The 'boxOpen' function verifies and decrypts a ciphertext
-- 'V.Vector' using the receiver's secret key, the sender's public
-- key, and a nonce. If the ciphertext fails verification, 'boxOpen'
-- returns 'Nothing'.
-- 
-- The "Crypto.Saltine.Internal.Box" module is designed to meet the
-- standard notions of privacy and third-party unforgeability for a
-- public-key authenticated-encryption scheme using nonces. For formal
-- definitions see, e.g., Jee Hea An, "Authenticated encryption in the
-- public-key setting: security notions and analyses,"
-- <http://eprint.iacr.org/2001/079>.
-- 
-- Distinct messages between the same @{sender, receiver}@ set are
-- required to have distinct nonces. For example, the
-- lexicographically smaller public key can use nonce 1 for its first
-- message to the other key, nonce 3 for its second message, nonce 5
-- for its third message, etc., while the lexicographically larger
-- public key uses nonce 2 for its first message to the other key,
-- nonce 4 for its second message, nonce 6 for its third message,
-- etc. Nonces are long enough that randomly generated nonces have
-- negligible risk of collision.
-- 
-- There is no harm in having the same nonce for different messages if
-- the @{sender, receiver}@ sets are different. This is true even if
-- the sets overlap. For example, a sender can use the same nonce for
-- two different messages if the messages are sent to two different
-- public keys.
-- 
-- The "Crypto.Saltine.Internal.Box" module is not meant to provide
-- non-repudiation. On the contrary: the crypto_box function
-- guarantees repudiability. A receiver can freely modify a boxed
-- message, and therefore cannot convince third parties that this
-- particular message came from the sender. The sender and receiver
-- are nevertheless protected against forgeries by other parties. In
-- the terminology of
-- <http://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c>,
-- crypto_box uses "public-key authenticators" rather than "public-key
-- signatures."
-- 
-- Users who want public verifiability (or receiver-assisted public
-- verifiability) should instead use signatures (or
-- signcryption). Signatures are documented in the
-- "Crypto.Saltine.Internal.Sign" module.
-- 
-- "Crypto.Saltine.Internal.Box" is @curve25519xsalsa20poly1305@, a
-- particular combination of Curve25519, Salsa20, and Poly1305
-- specified in "Cryptography in NaCl"
-- (<http://nacl.cr.yp.to/valid.html>). This function is conjectured
-- to meet the standard notions of privacy and third-party
-- unforgeability.
module Crypto.Saltine.Internal.Box (
  newKeypair, beforeNM, newNonce,
  box, boxOpen,
  boxAfterNM, boxOpenAfterNM  
  ) where

import Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import Foreign.C
import Foreign.Ptr
import Data.Word
import qualified Data.Vector.Storable as V

-- | Randomly generates a secret key and a corresponding public key as
-- @(secretKey, publicKey)@.
newKeypair :: IO (V.Vector Word8, V.Vector Word8) 
newKeypair = do
  -- This is a little bizarre and a likely source of errors.
  -- _err ought to always be 0.
  ((_err, sk), pk) <- buildUnsafeCVector' Bytes.boxPK $ \pkbuf ->
    buildUnsafeCVector' Bytes.boxSK $ \skbuf ->
    c_box_keypair pkbuf skbuf
  return (sk, pk)

beforeNM :: V.Vector Word8
            -- ^ Your secret key
            -> V.Vector Word8
            -- ^ Your correspondant's public key
            -> V.Vector Word8
            -- ^ The combined key
beforeNM sk pk = snd $ buildUnsafeCVector Bytes.boxBeforeNM $ \ckbuf ->
  constVectors [pk, sk] $ \[ppk, psk] ->
  c_box_beforenm ckbuf ppk psk

-- | Randomly generates a nonce for usage with 'box' and 'boxOpen'.
newNonce :: IO (V.Vector Word8)
newNonce = randomVector Bytes.boxNonce

-- | Executes @crypto_box@ on the passed 'V.Vector's. THIS IS MEMORY
-- UNSAFE unless the key and nonce are precisely the right sizes.
box :: V.Vector Word8
       -- ^ Public key
       -> V.Vector Word8
       -- ^ Secret key
       -> V.Vector Word8
       -- ^ Nonce
       -> V.Vector Word8
       -- ^ Message
       -> V.Vector Word8
       -- ^ Ciphertext
box pk sk nonce msg =
  unpad' . snd . buildUnsafeCVector len $ \pc ->
    constVectors [pk, sk, pad' msg, nonce] $ \[ppk, psk, pm, pn] ->
    c_box pc pm (fromIntegral len) pn ppk psk
  where len    = V.length msg + Bytes.boxZero
        pad'   = pad Bytes.boxZero
        unpad' = unpad Bytes.boxBoxZero

-- | Executes @crypto_box_open@ on the passed 'V.Vector's. THIS
-- IS MEMORY UNSAFE unless the key and nonce are precisely the right
-- sizes.
boxOpen :: V.Vector Word8
           -- ^ Public key
           -> V.Vector Word8
           -- ^ Secert key
           -> V.Vector Word8
           -- ^ Nonce
           -> V.Vector Word8
           -- ^ Ciphertext
           -> Maybe (V.Vector Word8)
           -- ^ Message
boxOpen pk sk nonce cipher =
  let (err, vec) = buildUnsafeCVector len $ \pm ->
        constVectors [pk, sk, pad' cipher, nonce] $ \[ppk, psk, pc, pn] ->
        c_box_open pm pc (fromIntegral len) pn ppk psk
  in hush . handleErrno err $ unpad' vec
  where len    = V.length cipher + Bytes.boxBoxZero
        pad'   = pad Bytes.boxBoxZero
        unpad' = unpad Bytes.boxZero

-- | Executes @crypto_box_afternm@ on the passed 'V.Vector's. THIS IS
-- MEMORY UNSAFE unless the key and nonce are precisely the right
-- sizes.
boxAfterNM :: V.Vector Word8
              -- ^ Public key
              -> V.Vector Word8
              -- ^ Nonce
              -> V.Vector Word8
              -- ^ Message
              -> V.Vector Word8
              -- ^ Ciphertext
boxAfterNM ck nonce msg =
  unpad' . snd . buildUnsafeCVector len $ \pc ->
    constVectors [ck, pad' msg, nonce] $ \[pck, pm, pn] ->
    c_box_afternm pc pm (fromIntegral len) pn pck
  where len    = V.length msg + Bytes.boxZero
        pad'   = pad Bytes.boxZero
        unpad' = unpad Bytes.boxBoxZero


-- | Executes @crypto_box_afternm_open@ on the passed
-- 'V.Vector's. THIS IS MEMORY UNSAFE unless the key and nonce are
-- precisely the right sizes.
boxOpenAfterNM :: V.Vector Word8
           -- ^ Public key
           -> V.Vector Word8
           -- ^ Nonce
           -> V.Vector Word8
           -- ^ Ciphertext
           -> Maybe (V.Vector Word8)
           -- ^ Message
boxOpenAfterNM ck nonce cipher =
  let (err, vec) = buildUnsafeCVector len $ \pm ->
        constVectors [ck, pad' cipher, nonce] $ \[pck, pc, pn] ->
        c_box_open_afternm pm pc (fromIntegral len) pn pck
  in hush . handleErrno err $ unpad' vec
  where len    = V.length cipher + Bytes.boxBoxZero
        pad'   = pad Bytes.boxBoxZero
        unpad' = unpad Bytes.boxZero


-- | Should always return a 0.
foreign import ccall "crypto_box_keypair"
  c_box_keypair :: Ptr Word8
                   -- ^ Public key
                   -> Ptr Word8
                   -- ^ Secret key
                   -> IO CInt
                   -- ^ Always 0

-- | The secretbox C API uses 0-padded C strings.
foreign import ccall "crypto_box"
  c_box :: Ptr Word8
           -- ^ Cipher 0-padded output buffer
           -> Ptr Word8
           -- ^ Constant 0-padded message input buffer
           -> CInt
           -- ^ Length of message input buffer (incl. 0s)
           -> Ptr Word8
           -- ^ Constant nonce buffer
           -> Ptr Word8
           -- ^ Constant public key buffer
           -> Ptr Word8
           -- ^ Constant secret key buffer
           -> IO CInt
           -- ^ Always 0

-- | The secretbox C API uses 0-padded C strings.
foreign import ccall "crypto_box_open"
  c_box_open :: Ptr Word8
                -- ^ Message 0-padded output buffer
                -> Ptr Word8
                -- ^ Constant 0-padded ciphertext input buffer
                -> CInt
                -- ^ Length of message input buffer (incl. 0s)
                -> Ptr Word8
                -- ^ Constant nonce buffer
                -> Ptr Word8
                -- ^ Constant public key buffer
                -> Ptr Word8
                -- ^ Constant secret key buffer
                -> IO CInt
                -- ^ 0 for success, -1 for failure to verify

-- | Single target key precompilation.
foreign import ccall "crypto_box_beforenm"
  c_box_beforenm :: Ptr Word8
                    -- ^ Combined key output buffer
                    -> Ptr Word8
                    -- ^ Constant public key buffer
                    -> Ptr Word8
                    -- ^ Constant secret key buffer
                    -> IO CInt
                    -- ^ Always 0

-- | Precompiled key crypto box. Uses 0-padded C strings.
foreign import ccall "crypto_box_afternm"
  c_box_afternm :: Ptr Word8
                   -- ^ Cipher 0-padded output buffer
                   -> Ptr Word8
                   -- ^ Constant 0-padded message input buffer
                   -> CInt
                   -- ^ Length of message input buffer (incl. 0s)
                   -> Ptr Word8
                   -- ^ Constant nonce buffer
                   -> Ptr Word8
                   -- ^ Constant combined key buffer
                   -> IO CInt
                   -- ^ Always 0

-- | The secretbox C API uses 0-padded C strings.
foreign import ccall "crypto_box_open_afternm"
  c_box_open_afternm :: Ptr Word8
                        -- ^ Message 0-padded output buffer
                        -> Ptr Word8
                        -- ^ Constant 0-padded ciphertext input buffer
                        -> CInt
                        -- ^ Length of message input buffer (incl. 0s)
                        -> Ptr Word8
                        -- ^ Constant nonce buffer
                        -> Ptr Word8
                        -- ^ Constant combined key buffer
                        -> IO CInt
                        -- ^ 0 for success, -1 for failure to verify
-- |
-- Module      : Crypto.Saltine.Core.Box
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Public-key cryptography abstraction:
-- "Crypto.Saltine.Core.Box"
--
-- This module consists of functions dealing with two public-key
-- cryptography concepts in libsodium.
--
-- The first one is an authenticated encryption scheme. In this
-- scheme, the 'box' function encrypts and authenticates a message
-- 'ByteString' using the sender's secret key, the receiver's public
-- key, and a nonce. The 'boxOpen' function verifies and decrypts a
-- ciphertext 'ByteString' using the receiver's secret key, the
-- sender's public key, and a nonce. If the ciphertext fails
-- verification, 'boxOpen' returns 'Nothing'.
--
-- The set of box functions is designed to meet the
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
-- The second concept is sealed boxes, which provide encryption and
-- preservation of integrity, but not authentication. Technically,
-- the sender of a message generates a keypair, uses the regular
-- box mechanism, attaches the public key to the message and then
-- immediately destroys the private key. This is useful, e.g. when
-- the receiver cannot know the sender's public key in advance and
-- hence cannot use the regular box functions, or when you want to
-- send messages anonymously.
--
-- The "Crypto.Saltine.Core.Box" module is not meant to provide
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
-- "Crypto.Saltine.Core.Sign" module.
--
-- "Crypto.Saltine.Core.Box" is @curve25519xsalsa20poly1305@, a
-- particular combination of Curve25519, Salsa20, and Poly1305
-- specified in "Cryptography in NaCl"
-- (<http://nacl.cr.yp.to/valid.html>). This function is conjectured
-- to meet the standard notions of privacy and third-party
-- unforgeability.
--
-- This is version 2010.08.30 of the box.html web page.
module Crypto.Saltine.Core.Box (
  SecretKey, PublicKey, Keypair, CombinedKey, Nonce,
  newKeypair, beforeNM, newNonce,
  box, boxOpen,
  boxAfterNM, boxOpenAfterNM,
  boxSeal, boxSealOpen
  ) where

import           Crypto.Saltine.Class
import           Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import           Foreign.C
import           Foreign.Ptr
import qualified Data.ByteString                   as S
import           Data.ByteString (ByteString)


-- $types

-- | An opaque 'box' cryptographic secret key.
newtype SecretKey = SK ByteString deriving (Eq, Ord)

instance IsEncoding SecretKey where
  decode v = if S.length v == Bytes.boxSK
           then Just (SK v)
           else Nothing
  {-# INLINE decode #-}
  encode (SK v) = v
  {-# INLINE encode #-}

-- | An opaque 'box' cryptographic public key.
newtype PublicKey = PK ByteString deriving (Eq, Ord)

instance IsEncoding PublicKey where
  decode v = if S.length v == Bytes.boxPK
           then Just (PK v)
           else Nothing
  {-# INLINE decode #-}
  encode (PK v) = v
  {-# INLINE encode #-}

-- | A convenience type for keypairs
type Keypair = (SecretKey, PublicKey)

-- | An opaque 'boxAfterNM' cryptographic combined key.
newtype CombinedKey = CK ByteString deriving (Eq, Ord)

instance IsEncoding CombinedKey where
  decode v = if S.length v == Bytes.boxBeforeNM
           then Just (CK v)
           else Nothing
  {-# INLINE decode #-}
  encode (CK v) = v
  {-# INLINE encode #-}

-- | An opaque 'box' nonce.
newtype Nonce = Nonce ByteString deriving (Eq, Ord)

instance IsEncoding Nonce where
  decode v = if S.length v == Bytes.boxNonce
           then Just (Nonce v)
           else Nothing
  {-# INLINE decode #-}
  encode (Nonce v) = v
  {-# INLINE encode #-}

instance IsNonce Nonce where
  zero            = Nonce (S.replicate Bytes.boxNonce 0)
  nudge (Nonce n) = Nonce (nudgeBS n)

-- | Randomly generates a secret key and a corresponding public key.
newKeypair :: IO Keypair
newKeypair = do
  -- This is a little bizarre and a likely source of errors.
  -- _err ought to always be 0.
  ((_err, sk), pk) <- buildUnsafeCVector' Bytes.boxPK $ \pkbuf ->
    buildUnsafeCVector' Bytes.boxSK $ \skbuf ->
      c_box_keypair pkbuf skbuf
  return (SK sk, PK pk)

-- | Randomly generates a nonce for usage with 'box' and 'boxOpen'.
newNonce :: IO Nonce
newNonce = Nonce <$> randomVector Bytes.boxNonce

-- | Build a 'CombinedKey' for sending from 'SecretKey' to
-- 'PublicKey'. This is a precomputation step which can accelerate
-- later encryption calls.
beforeNM :: SecretKey -> PublicKey -> CombinedKey
beforeNM (SK sk) (PK pk) = CK $ snd $ buildUnsafeCVector Bytes.boxBeforeNM $ \ckbuf ->
  constVectors [pk, sk] $ \[(ppk, _), (psk, _)] ->
    c_box_beforenm ckbuf ppk psk

-- | Encrypts a message for sending to the owner of the public
-- key. They must have your public key in order to decrypt the
-- message. It is infeasible for an attacker to decrypt the message so
-- long as the 'Nonce' is not repeated.
box :: PublicKey -> SecretKey -> Nonce
    -> ByteString
    -- ^ Message
    -> ByteString
    -- ^ Ciphertext
box (PK pk) (SK sk) (Nonce nonce) msg =
  unpad' . snd . buildUnsafeCVector len $ \pc ->
    constVectors [pk, sk, pad' msg, nonce] $ \
      [(ppk, _), (psk, _), (pm, _), (pn, _)] ->
        c_box pc pm (fromIntegral len) pn ppk psk
  where len    = S.length msg + Bytes.boxZero
        pad'   = pad Bytes.boxZero
        unpad' = unpad Bytes.boxBoxZero

-- | Decrypts a message sent from the owner of the public key. They
-- must have encrypted it using your secret key. Returns 'Nothing' if
-- the keys and message do not match.
boxOpen :: PublicKey -> SecretKey -> Nonce
        -> ByteString
        -- ^ Ciphertext
        -> Maybe ByteString
        -- ^ Message
boxOpen (PK pk) (SK sk) (Nonce nonce) cipher =
  let (err, vec) = buildUnsafeCVector len $ \pm ->
        constVectors [pk, sk, pad' cipher, nonce] $ \
          [(ppk, _), (psk, _), (pc, _), (pn, _)] ->
            c_box_open pm pc (fromIntegral len) pn ppk psk
  in hush . handleErrno err $ unpad' vec
  where len    = S.length cipher + Bytes.boxBoxZero
        pad'   = pad Bytes.boxBoxZero
        unpad' = unpad Bytes.boxZero

-- | 'box' using a 'CombinedKey' and is thus faster.
boxAfterNM :: CombinedKey -> Nonce
           -> ByteString
           -- ^ Message
           -> ByteString
           -- ^ Ciphertext
boxAfterNM (CK ck) (Nonce nonce) msg =
  unpad' . snd . buildUnsafeCVector len $ \pc ->
    constVectors [ck, pad' msg, nonce] $ \
      [(pck, _), (pm, _), (pn, _)] ->
        c_box_afternm pc pm (fromIntegral len) pn pck
  where len    = S.length msg + Bytes.boxZero
        pad'   = pad Bytes.boxZero
        unpad' = unpad Bytes.boxBoxZero

-- | 'boxOpen' using a 'CombinedKey' and is thus faster.
boxOpenAfterNM :: CombinedKey -> Nonce
               -> ByteString
               -- ^ Ciphertext
               -> Maybe ByteString
               -- ^ Message
boxOpenAfterNM (CK ck) (Nonce nonce) cipher =
  let (err, vec) = buildUnsafeCVector len $ \pm ->
        constVectors [ck, pad' cipher, nonce] $ \
          [(pck, _), (pc, _), (pn, _)] ->
            c_box_open_afternm pm pc (fromIntegral len) pn pck
  in hush . handleErrno err $ unpad' vec
  where len    = S.length cipher + Bytes.boxBoxZero
        pad'   = pad Bytes.boxBoxZero
        unpad' = unpad Bytes.boxZero


-- | Encrypts a message for sending to the owner of the public
-- key. The message is unauthenticated, but permits integrity checking.
boxSeal :: PublicKey -> ByteString -> IO ByteString
boxSeal (PK pk) msg = return $
  snd . buildUnsafeCVector strlen $ \pc ->
    constVectors [pk, msg] $ \
      [(ppk, _), (pm, _)] ->
        c_box_seal pc pm (fromIntegral len) ppk
  where strlen    = S.length msg + Bytes.sealedBox
        len       = S.length msg

-- | Decrypts a sealed box message. The message must have been
-- encrypted using the receiver's public key.
-- Returns 'Nothing' if keys and message do not match or integrity
-- is violated.
boxSealOpen :: PublicKey -> SecretKey
            -> ByteString
            -- ^ Ciphertext
            -> Maybe ByteString
            -- ^ Message
boxSealOpen (PK pk) (SK sk) cipher =
  let (err, vec) = buildUnsafeCVector strlen $ \pm ->
        constVectors [pk, sk, cipher] $ \
          [(ppk, _), (psk, _), (pc, _)] ->
          c_box_seal_open pm pc (fromIntegral len) ppk psk
  in hush . handleErrno err $ vec
  where strlen    = S.length cipher - Bytes.sealedBox
        len       = S.length cipher


-- | Should always return a 0.
foreign import ccall "crypto_box_keypair"
  c_box_keypair :: Ptr CChar
                -- ^ Public key
                -> Ptr CChar
                -- ^ Secret key
                -> IO CInt
                -- ^ Always 0

-- | The secretbox C API uses 0-padded C strings.
foreign import ccall "crypto_box"
  c_box :: Ptr CChar
        -- ^ Cipher 0-padded output buffer
        -> Ptr CChar
        -- ^ Constant 0-padded message input buffer
        -> CULLong
        -- ^ Length of message input buffer (incl. 0s)
        -> Ptr CChar
        -- ^ Constant nonce buffer
        -> Ptr CChar
        -- ^ Constant public key buffer
        -> Ptr CChar
        -- ^ Constant secret key buffer
        -> IO CInt
        -- ^ Always 0

-- | The secretbox C API uses 0-padded C strings.
foreign import ccall "crypto_box_open"
  c_box_open :: Ptr CChar
             -- ^ Message 0-padded output buffer
             -> Ptr CChar
             -- ^ Constant 0-padded ciphertext input buffer
             -> CULLong
             -- ^ Length of message input buffer (incl. 0s)
             -> Ptr CChar
             -- ^ Constant nonce buffer
             -> Ptr CChar
             -- ^ Constant public key buffer
             -> Ptr CChar
             -- ^ Constant secret key buffer
             -> IO CInt
             -- ^ 0 for success, -1 for failure to verify

-- | Single target key precompilation.
foreign import ccall "crypto_box_beforenm"
  c_box_beforenm :: Ptr CChar
                 -- ^ Combined key output buffer
                 -> Ptr CChar
                 -- ^ Constant public key buffer
                 -> Ptr CChar
                 -- ^ Constant secret key buffer
                 -> IO CInt
                 -- ^ Always 0

-- | Precompiled key crypto box. Uses 0-padded C strings.
foreign import ccall "crypto_box_afternm"
  c_box_afternm :: Ptr CChar
                -- ^ Cipher 0-padded output buffer
                -> Ptr CChar
                -- ^ Constant 0-padded message input buffer
                -> CULLong
                -- ^ Length of message input buffer (incl. 0s)
                -> Ptr CChar
                -- ^ Constant nonce buffer
                -> Ptr CChar
                -- ^ Constant combined key buffer
                -> IO CInt
                -- ^ Always 0

-- | The secretbox C API uses 0-padded C strings.
foreign import ccall "crypto_box_open_afternm"
  c_box_open_afternm :: Ptr CChar
                     -- ^ Message 0-padded output buffer
                     -> Ptr CChar
                     -- ^ Constant 0-padded ciphertext input buffer
                     -> CULLong
                     -- ^ Length of message input buffer (incl. 0s)
                     -> Ptr CChar
                     -- ^ Constant nonce buffer
                     -> Ptr CChar
                     -- ^ Constant combined key buffer
                     -> IO CInt
                     -- ^ 0 for success, -1 for failure to verify


-- | The sealedbox C API uses C strings.
foreign import ccall "crypto_box_seal"
  c_box_seal :: Ptr CChar
             -- ^ Cipher output buffer
             -> Ptr CChar
             -- ^ Constant message input buffer
             -> CULLong
             -- ^ Length of message input buffer
             -> Ptr CChar
             -- ^ Constant public key buffer
             -> IO CInt
             -- ^ Always 0

-- | The sealedbox C API uses C strings.
foreign import ccall "crypto_box_seal_open"
  c_box_seal_open :: Ptr CChar
                  -- ^ Message output buffer
                  -> Ptr CChar
                  -- ^ Constant ciphertext input buffer
                  -> CULLong
                  -- ^ Length of message input buffer
                  -> Ptr CChar
                  -- ^ Constant public key buffer
                  -> Ptr CChar
                  -- ^ Constant secret key buffer
                  -> IO CInt
                  -- ^ 0 for success, -1 for failure to decrypt

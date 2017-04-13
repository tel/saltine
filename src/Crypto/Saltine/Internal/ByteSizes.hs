{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Core.ScalarMult
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Various sizes
--
-- While technically these sizes are hidden behind opaque newtype
-- wrappers, they can be useful for computation and sizing and are
-- thus exposed.
--
-- As of @libsodium-4.1@ some of these sizes are not exported and thus
-- are hardcoded here. This limitation should be removed in later
-- versions of @libsodium@.
module Crypto.Saltine.Internal.ByteSizes (

  auth,
  authKey,
  boxPK,
  boxSK,
  boxNonce,
  boxZero,
  boxBoxZero,
  boxMac,
  boxBeforeNM,
  sealedBox,
  onetime,
  onetimeKey,
  mult,
  multScalar,
  secretBoxKey,
  secretBoxNonce,
  secretBoxZero,
  secretBoxBoxZero,
  sign,
  signPK,
  signSK,
  streamKey,
  streamNonce,
  hash,
  shorthash,
  shorthashKey
  ) where

import Foreign.C

-- Constants for

auth, authKey :: Int
boxPK, boxSK, boxNonce, boxZero, boxBoxZero :: Int
boxMac, boxBeforeNM, sealedBox :: Int
onetime, onetimeKey :: Int
mult, multScalar :: Int
secretBoxKey, secretBoxNonce, secretBoxZero, secretBoxBoxZero :: Int
sign, signPK, signSK :: Int
streamKey, streamNonce :: Int
hash, shorthash, shorthashKey :: Int


-- Authentication
-- | Size of a @crypto_auth@ authenticator.
auth    = fromIntegral c_crypto_auth_bytes
-- | Size of a @crypto_auth@ authenticator key.
authKey = fromIntegral c_crypto_auth_keybytes

-- Box
-- | Size of a @crypto_box@ public key
boxPK       = fromIntegral c_crypto_box_publickeybytes
-- | Size of a @crypto_box@ secret key
boxSK       = fromIntegral c_crypto_box_secretkeybytes
-- | Size of a @crypto_box@ nonce
boxNonce    = fromIntegral c_crypto_box_noncebytes
-- | Size of 0-padding prepended to messages before using @crypto_box@
-- or after using @crypto_box_open@
boxZero     = fromIntegral c_crypto_box_zerobytes
-- | Size of 0-padding prepended to ciphertext before using
-- @crypto_box_open@ or after using @crypto_box@.
boxBoxZero  = fromIntegral c_crypto_box_boxzerobytes
boxMac      = fromIntegral c_crypto_box_macbytes
-- | Size of a @crypto_box_beforenm@-generated combined key
boxBeforeNM =
  fromIntegral c_crypto_box_beforenmbytes

-- SealedBox
-- | Amount by which ciphertext is longer than plaintext
-- in sealed boxes
sealedBox = fromIntegral c_crypto_box_sealbytes

-- OneTimeAuth
-- | Size of a @crypto_onetimeauth@ authenticator.
onetime    = fromIntegral c_crypto_onetimeauth_bytes
-- | Size of a @crypto_onetimeauth@ authenticator key.
onetimeKey = fromIntegral c_crypto_onetimeauth_keybytes

-- ScalarMult
-- | Size of a group element string representation for
-- @crypto_scalarmult@.
mult = fromIntegral c_crypto_scalarmult_bytes
-- | Size of a integer string representation for @crypto_scalarmult@.
multScalar = fromIntegral c_crypto_scalarmult_scalarbytes

-- SecretBox
-- | Size of a @crypto_secretbox@ secret key
secretBoxKey     = fromIntegral c_crypto_secretbox_keybytes
-- | Size of a @crypto_secretbox@ nonce
secretBoxNonce   = fromIntegral c_crypto_secretbox_noncebytes
-- | Size of 0-padding prepended to messages before using
-- @crypto_secretbox@ or after using @crypto_secretbox_open@
secretBoxZero    = fromIntegral c_crypto_secretbox_zerobytes
-- | Size of 0-padding prepended to ciphertext before using
-- @crypto_secretbox_open@ or after using @crypto_secretbox@
secretBoxBoxZero = fromIntegral c_crypto_secretbox_boxzerobytes

-- Signatures
-- | The maximum size of a signature prepended to a message to form a
-- signed message.
sign   = fromIntegral c_crypto_sign_bytes
-- | The size of a public key for signing verification
signPK = fromIntegral c_crypto_sign_publickeybytes
-- | The size of a secret key for signing
signSK = fromIntegral c_crypto_sign_secretkeybytes

-- Streams
-- | The size of a key for the cryptographic stream generation
streamKey   = fromIntegral c_crypto_stream_keybytes
-- | The size of a nonce for the cryptographic stream generation
streamNonce = fromIntegral c_crypto_stream_noncebytes

-- Hashes
-- | The size of a hash resulting from
-- 'Crypto.Saltine.Internal.Hash.hash'.
hash         = fromIntegral c_crypto_hash_bytes
-- | The size of a keyed hash resulting from
-- 'Crypto.Saltine.Internal.Hash.shorthash'.
shorthash    = fromIntegral c_crypto_shorthash_bytes
-- | The size of a hashing key for the keyed hash function
-- 'Crypto.Saltine.Internal.Hash.shorthash'.
shorthashKey = fromIntegral c_crypto_shorthash_keybytes

-- src/libsodium/crypto_auth/crypto_auth.c
foreign import ccall "crypto_auth_bytes"
  c_crypto_auth_bytes :: CSize
foreign import ccall "crypto_auth_keybytes"
  c_crypto_auth_keybytes :: CSize

-- src/libsodium/crypto_box/crypto_box.c
foreign import ccall "crypto_box_publickeybytes"
  c_crypto_box_publickeybytes :: CSize
foreign import ccall "crypto_box_secretkeybytes"
  c_crypto_box_secretkeybytes :: CSize
foreign import ccall "crypto_box_beforenmbytes"
  c_crypto_box_beforenmbytes :: CSize
foreign import ccall "crypto_box_noncebytes"
  c_crypto_box_noncebytes :: CSize
foreign import ccall "crypto_box_zerobytes"
  c_crypto_box_zerobytes :: CSize
foreign import ccall "crypto_box_boxzerobytes"
  c_crypto_box_boxzerobytes :: CSize
foreign import ccall "crypto_box_macbytes"
  c_crypto_box_macbytes :: CSize

-- src/libsodium/crypto_box_seal.c
foreign import ccall "crypto_box_sealbytes"
  c_crypto_box_sealbytes :: CSize

-- src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c
foreign import ccall "crypto_onetimeauth_bytes"
  c_crypto_onetimeauth_bytes :: CSize
foreign import ccall "crypto_onetimeauth_keybytes"
  c_crypto_onetimeauth_keybytes :: CSize

-- src/libsodium/crypto_scalarmult/crypto_scalarmult.c
foreign import ccall "crypto_scalarmult_bytes"
  c_crypto_scalarmult_bytes :: CSize
foreign import ccall "crypto_scalarmult_scalarbytes"
  c_crypto_scalarmult_scalarbytes :: CSize

-- src/libsodium/crypto_secretbox/crypto_secretbox.c
foreign import ccall "crypto_secretbox_keybytes"
  c_crypto_secretbox_keybytes :: CSize
foreign import ccall "crypto_secretbox_noncebytes"
  c_crypto_secretbox_noncebytes :: CSize
foreign import ccall "crypto_secretbox_zerobytes"
  c_crypto_secretbox_zerobytes :: CSize
foreign import ccall "crypto_secretbox_boxzerobytes"
  c_crypto_secretbox_boxzerobytes :: CSize

-- src/libsodium/crypto_sign/crypto_sign.c
foreign import ccall "crypto_sign_bytes"
  c_crypto_sign_bytes :: CSize
foreign import ccall "crypto_sign_publickeybytes"
  c_crypto_sign_publickeybytes :: CSize
foreign import ccall "crypto_sign_secretkeybytes"
  c_crypto_sign_secretkeybytes :: CSize

-- HARDCODED
-- ---------

-- | The size of a @crypto_stream@ or @crypto_stream_xor@
-- key. HARDCODED to be @crypto_stream_xsalsa20@ for now until Sodium
-- exports the C constant.
c_crypto_stream_keybytes :: CSize
c_crypto_stream_keybytes = 32

-- | The size of a @crypto_stream@ or @crypto_stream_xor@
-- nonce. HARDCODED to be @crypto_stream_xsalsa20@ for now until
-- Sodium exports the C constant.
c_crypto_stream_noncebytes :: CSize
c_crypto_stream_noncebytes = 24

-- | The size of a @crypto_hash@ output hash. HARDCODED to be
-- @crypto_hash_sha512@ for now until Sodium exports the C constant.
c_crypto_hash_bytes :: CSize
c_crypto_hash_bytes = 64

-- | The size of a @crypto_shorthash@ output hash. HARDCODED to be
-- @crypto_shorthash_siphash24@ for now until Sodium exports the C
-- constant.
c_crypto_shorthash_bytes :: CSize
c_crypto_shorthash_bytes = 8

-- | The size of a @crypto_shorthash@ key. HARDCODED to be
-- @crypto_shorthash_siphash24@ for now until Sodium exports the C
-- constant.
c_crypto_shorthash_keybytes :: CSize
c_crypto_shorthash_keybytes = 16


-- src/libsodium/crypto_stream/crypto_stream.c
-- foreign import ccall "crypto_stream_keybytes"
--   c_crypto_stream_keybytes :: CSize
-- foreign import ccall "crypto_stream_noncebytes"
--   c_crypto_stream_noncebytes :: CSize

-- src/libsodium/crypto_shorthash/crypto_shorthash.c
-- foreign import ccall "crypto_shorthash_bytes"
--   c_crypto_shorthash_bytes :: CSize
-- foreign import ccall "crypto_shorthash_keybytes"
--   c_crypto_shorthash_keybytes :: CSize

-- Others
-- ------

-- src/libsodium/crypto_auth/hmacsha256/auth_hmacsha256_api.c
-- foreign import ccall "crypto_auth_hmacsha256_bytes"
--   c_crypto_auth_hmacsha256_bytes :: CSize
-- foreign import ccall "crypto_auth_hmacsha256_keybytes"
--   c_crypto_auth_hmacsha256_keybytes :: CSize

-- src/libsodium/crypto_auth/hmacsha512256/auth_hmacsha512256_api.c
-- foreign import ccall "crypto_auth_hmacsha512256_bytes"
--   c_crypto_auth_hmacsha512256_bytes :: CSize
-- foreign import ccall "crypto_auth_hmacsha512256_keybytes"
--   c_crypto_auth_hmacsha512256_keybytes :: CSize

-- src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305_api.c
-- foreign import ccall "crypto_box_curve25519xsalsa20poly1305_publickeybytes"
--   c_crypto_box_curve25519xsalsa20poly1305_publickeybytes :: CSize
-- foreign import ccall "crypto_box_curve25519xsalsa20poly1305_secretkeybytes"
--   c_crypto_box_curve25519xsalsa20poly1305_secretkeybytes :: CSize
-- foreign import ccall "crypto_box_curve25519xsalsa20poly1305_beforenmbytes"
--   c_crypto_box_curve25519xsalsa20poly1305_beforenmbytes :: CSize
-- foreign import ccall "crypto_box_curve25519xsalsa20poly1305_noncebytes"
--   c_crypto_box_curve25519xsalsa20poly1305_noncebytes :: CSize
-- foreign import ccall "crypto_box_curve25519xsalsa20poly1305_zerobytes"
--   c_crypto_box_curve25519xsalsa20poly1305_zerobytes :: CSize
-- foreign import ccall "crypto_box_curve25519xsalsa20poly1305_boxzerobytes"
--   c_crypto_box_curve25519xsalsa20poly1305_boxzerobytes :: CSize
-- foreign import ccall "crypto_box_curve25519xsalsa20poly1305_macbytes"
--   c_crypto_box_curve25519xsalsa20poly1305_macbytes :: CSize

-- src/libsodium/crypto_core/hsalsa20/core_hsalsa20_api.c
-- foreign import ccall "crypto_core_hsalsa20_outputbytes"
--   c_crypto_core_hsalsa20_outputbytes :: CSize
-- foreign import ccall "crypto_core_hsalsa20_inputbytes"
--   c_crypto_core_hsalsa20_inputbytes :: CSize
-- foreign import ccall "crypto_core_hsalsa20_keybytes"
--   c_crypto_core_hsalsa20_keybytes :: CSize
-- foreign import ccall "crypto_core_hsalsa20_constbytes"
--   c_crypto_core_hsalsa20_constbytes :: CSize

-- src/libsodium/crypto_core/salsa20/core_salsa20_api.c
-- foreign import ccall "crypto_core_salsa20_outputbytes"
--   c_crypto_core_salsa20_outputbytes :: CSize
-- foreign import ccall "crypto_core_salsa20_inputbytes"
--   c_crypto_core_salsa20_inputbytes :: CSize
-- foreign import ccall "crypto_core_salsa20_keybytes"
--   c_crypto_core_salsa20_keybytes :: CSize
-- foreign import ccall "crypto_core_salsa20_constbytes"
--   c_crypto_core_salsa20_constbytes :: CSize

-- src/libsodium/crypto_core/salsa2012/core_salsa2012_api.c
-- foreign import ccall "crypto_core_salsa2012_outputbytes"
--   c_crypto_core_salsa2012_outputbytes :: CSize
-- foreign import ccall "crypto_core_salsa2012_inputbytes"
--   c_crypto_core_salsa2012_inputbytes :: CSize
-- foreign import ccall "crypto_core_salsa2012_keybytes"
--   c_crypto_core_salsa2012_keybytes :: CSize
-- foreign import ccall "crypto_core_salsa2012_constbytes"
--   c_crypto_core_salsa2012_constbytes :: CSize

-- src/libsodium/crypto_core/salsa208/core_salsa208_api.c
-- foreign import ccall "crypto_core_salsa208_outputbytes"
--   c_crypto_core_salsa208_outputbytes :: CSize
-- foreign import ccall "crypto_core_salsa208_inputbytes"
--   c_crypto_core_salsa208_inputbytes :: CSize
-- foreign import ccall "crypto_core_salsa208_keybytes"
--   c_crypto_core_salsa208_keybytes :: CSize
-- foreign import ccall "crypto_core_salsa208_constbytes"
--   c_crypto_core_salsa208_constbytes :: CSize

-- src/libsodium/crypto_generichash/blake2/generichash_blake2_api.c
-- foreign import ccall "crypto_generichash_blake2b_blockbytes"
--   c_crypto_generichash_blake2b_blockbytes :: CSize

-- src/libsodium/crypto_generichash/crypto_generichash.c
-- foreign import ccall "crypto_generichash_bytes"
--   c_crypto_generichash_bytes :: CSize
-- foreign import ccall "crypto_generichash_keybytes"
--   c_crypto_generichash_keybytes :: CSize
-- foreign import ccall "crypto_generichash_blockbytes"
--   c_crypto_generichash_blockbytes :: CSize

-- src/libsodium/crypto_hash/sha256/hash_sha256_api.c
-- foreign import ccall "crypto_hash_sha256_bytes"
--   c_crypto_hash_sha256_bytes :: CSize

-- src/libsodium/crypto_hash/sha512/hash_sha512_api.c
-- foreign import ccall "crypto_hash_sha512_bytes"
--   c_crypto_hash_sha512_bytes :: CSize

-- src/libsodium/crypto_hashblocks/sha256/hashblocks_sha256_api.c
-- foreign import ccall "crypto_hashblocks_sha256_statebytes"
--   c_crypto_hashblocks_sha256_statebytes :: CSize
-- foreign import ccall "crypto_hashblocks_sha256_blockbytes"
--   c_crypto_hashblocks_sha256_blockbytes :: CSize

-- src/libsodium/crypto_hashblocks/sha512/hashblocks_sha512_api.c
-- foreign import ccall "crypto_hashblocks_sha512_statebytes"
--   c_crypto_hashblocks_sha512_statebytes :: CSize
-- foreign import ccall "crypto_hashblocks_sha512_blockbytes"
--   c_crypto_hashblocks_sha512_blockbytes :: CSize

-- src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305_api.c
-- foreign import ccall "crypto_onetimeauth_poly1305_bytes"
--   c_crypto_onetimeauth_poly1305_bytes :: CSize
-- foreign import ccall "crypto_onetimeauth_poly1305_keybytes"
--   c_crypto_onetimeauth_poly1305_keybytes :: CSize

-- src/libsodium/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305_api.c
-- foreign import ccall "crypto_secretbox_xsalsa20poly1305_keybytes"
--   c_crypto_secretbox_xsalsa20poly1305_keybytes :: CSize
-- foreign import ccall "crypto_secretbox_xsalsa20poly1305_noncebytes"
--   c_crypto_secretbox_xsalsa20poly1305_noncebytes :: CSize
-- foreign import ccall "crypto_secretbox_xsalsa20poly1305_zerobytes"
--   c_crypto_secretbox_xsalsa20poly1305_zerobytes :: CSize
-- foreign import ccall "crypto_secretbox_xsalsa20poly1305_boxzerobytes"
--   c_crypto_secretbox_xsalsa20poly1305_boxzerobytes :: CSize

-- foreign import ccall "crypto_shorthash_siphash24_bytes"
--   c_crypto_shorthash_siphash24_bytes :: CSize

-- src/libsodium/crypto_sign/ed25519/sign_ed25519_api.c
-- foreign import ccall "crypto_sign_ed25519_bytes"
--   c_crypto_sign_ed25519_bytes :: CSize
-- foreign import ccall "crypto_sign_ed25519_publickeybytes"
--   c_crypto_sign_ed25519_publickeybytes :: CSize
-- foreign import ccall "crypto_sign_ed25519_secretkeybytes"
--   c_crypto_sign_ed25519_secretkeybytes :: CSize

-- src/libsodium/crypto_sign/edwards25519sha512batch/sign_edwards25519sha512batch_api.c
-- foreign import ccall "crypto_sign_edwards25519sha512batch_bytes"
--   c_crypto_sign_edwards25519sha512batch_bytes :: CSize
-- foreign import ccall "crypto_sign_edwards25519sha512batch_publickeybytes"
--   c_crypto_sign_edwards25519sha512batch_publickeybytes :: CSize
-- foreign import ccall "crypto_sign_edwards25519sha512batch_secretkeybytes"
--   c_crypto_sign_edwards25519sha512batch_secretkeybytes :: CSize

-- src/libsodium/crypto_stream/aes128ctr/stream_aes128ctr_api.c
-- foreign import ccall "crypto_stream_aes128ctr_keybytes"
--   c_crypto_stream_aes128ctr_keybytes :: CSize
-- foreign import ccall "crypto_stream_aes128ctr_noncebytes"
--   c_crypto_stream_aes128ctr_noncebytes :: CSize
-- foreign import ccall "crypto_stream_aes128ctr_beforenmbytes"
--   c_crypto_stream_aes128ctr_beforenmbytes :: CSize

-- src/libsodium/crypto_stream/aes256estream/stream_aes256estream_api.c
-- foreign import ccall "crypto_stream_aes256estream_keybytes"
--   c_crypto_stream_aes256estream_keybytes :: CSize
-- foreign import ccall "crypto_stream_aes256estream_noncebytes"
--   c_crypto_stream_aes256estream_noncebytes :: CSize
-- foreign import ccall "crypto_stream_aes256estream_beforenmbytes"
--   c_crypto_stream_aes256estream_beforenmbytes :: CSize

-- src/libsodium/crypto_stream/salsa2012/stream_salsa2012_api.c
-- foreign import ccall "crypto_stream_salsa2012_keybytes"
--   c_crypto_stream_salsa2012_keybytes :: CSize
-- foreign import ccall "crypto_stream_salsa2012_noncebytes"
--   c_crypto_stream_salsa2012_noncebytes :: CSize

-- src/libsodium/crypto_stream/salsa208/stream_salsa208_api.c
-- foreign import ccall "crypto_stream_salsa208_keybytes"
--   c_crypto_stream_salsa208_keybytes :: CSize
-- foreign import ccall "crypto_stream_salsa208_noncebytes"
--   c_crypto_stream_salsa208_noncebytes :: CSize

-- src/libsodium/crypto_stream/xsalsa20/stream_xsalsa20_api.c
-- foreign import ccall "crypto_stream_xsalsa20_keybytes"
--   c_crypto_stream_xsalsa20_keybytes :: CSize
-- foreign import ccall "crypto_stream_xsalsa20_noncebytes"
--   c_crypto_stream_xsalsa20_noncebytes :: CSize

-- src/libsodium/crypto_verify/16/verify_16_api.c
-- foreign import ccall "crypto_verify_16_bytes"
--   c_crypto_verify_16_bytes :: CSize

-- src/libsodium/crypto_verify/32/verify_32_api.c
-- foreign import ccall "crypto_verify_32_bytes"
--   c_crypto_verify_32_bytes :: CSize

{-# LANGUAGE ForeignFunctionInterface #-}
-- |
-- Module      : Crypto.Saltine.Internal.ByteSizes
-- Copyright   : (c) Joseph Abrahamson 2013
--               (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
module Crypto.Saltine.Internal.ByteSizes (
  ) where

import Foreign.C



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

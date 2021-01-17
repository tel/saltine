-- |
-- Module      : Crypto.Saltine.Core.AEAD
-- Copyright   : (c) Thomas DuBuisson 2017
--               (c) Max Amanshauser 2021
-- License     : MIT
--
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
-- Secret-key authenticated encryption with additional data (AEAD):
-- "Crypto.Saltine.Core.AEAD"
--
-- The 'aead' function encrypts and authenticates a message
-- 'ByteString' and additional authenticated data 'ByteString'
-- using a secret key and a nonce. The 'aeadOpen'
-- function verifies and decrypts a ciphertext 'ByteString' using a
-- secret key and a nonce. If the ciphertext fails validation,
-- 'aeadOpen' returns 'Nothing'.
--
-- The "Crypto.Saltine.Core.AEAD" module is designed to meet
-- the standard notions of privacy and authenticity for a secret-key
-- authenticated-encryption scheme using nonces. For formal
-- definitions see, e.g., Bellare and Namprempre, "Authenticated
-- encryption: relations among notions and analysis of the generic
-- composition paradigm," Lecture Notes in Computer Science 1976
-- (2000), 531–545, <http://www-cse.ucsd.edu/~mihir/papers/oem.html>.
--
-- Note that the length is not hidden. Note also that it is the
-- caller's responsibility to ensure the uniqueness of nonces—for
-- example, by using nonce 1 for the first message, nonce 2 for the
-- second message, etc. With XChaCha20Poly1305 nonces are long enough
-- that you can also generate nonces randomly as they have negligible
-- risk of collision.
--
-- The keysize is identical for all the *ChaCha20Poly1305* variants,
-- but the nonce length differs. Since libsodium keeps separate definitions,
-- we do the same.
--
-- This module reexports the XChaCha20Poly1305 variant, which is the
-- recommended one.

module Crypto.Saltine.Core.AEAD (
  module X
  ) where

import Crypto.Saltine.Core.AEAD.XChaCha20Poly1305 as X

-- |
-- Module      : Crypto.Saltine.Core.Password
-- Description : Argon2 password hash
-- Copyright   : (c) Promethea Raschke 2018
--                   Max Amanshauser 2021
-- License     : MIT
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable
--
-- Password hashing and key derivation
--
-- When in doubt, just use one of [ interactivePolicy, moderatePolicy, sensitivePolicy ],
-- but this module also allows you to fine-tune parameters for specific circumstances.
--
-- This module uses the `Text` type for passwords, because this seems to be the only
-- reasonable way to get consistent encodings across locales and architectures, short of
-- letting users mess around with ByteStrings themselves.

module Crypto.Saltine.Core.Password
  ( Salt
  , newSalt

  , needsRehash

  , pwhashStr
  , pwhashStrVerify
  , pwhash

  , Policy(..)
  , interactivePolicy
  , moderatePolicy
  , sensitivePolicy

  , Opslimit
  , opslimit
  , getOpslimit

  , minOpslimit
  , maxOpslimit

  , opslimitInteractive
  , opslimitModerate
  , opslimitSensitive

  , Memlimit
  , memlimit
  , getMemlimit

  , minMemlimit
  , maxMemlimit

  , memlimitInteractive
  , memlimitModerate
  , memlimitSensitive

  , Algorithm
  , defaultAlgorithm
  ) where

import Crypto.Saltine.Internal.Util
import Crypto.Saltine.Internal.Password as I
import Data.ByteString (ByteString)
import Data.Text       (Text)
import Foreign.C
import System.IO.Unsafe

import qualified Crypto.Saltine.Internal.Password as Bytes
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE


newSalt :: IO Salt
newSalt = Salt <$> randomByteString Bytes.pwhash_saltbytes

-- | Hashes a password according to the policy
-- This function is non-deterministic and hence in IO.
-- Since this function may cause a huge amount of memory to be allocated, it will return
-- Nothing if the allocation failed and on any other error.
pwhashStr :: Text -> Policy -> IO (Maybe PasswordHash)
pwhashStr pw policy = do
  let (ops, mem, _alg) = unpackPolicy policy

  -- Hash is always ASCII, so no decoding needed
  fmap (fmap (PasswordHash . T.pack)) $ allocaBytes pwhash_strbytes $ \pp ->
    constByteStrings [TE.encodeUtf8 pw] $ \ [(ppw, ppwlen)] -> do
          ret <- c_pwhash_str pp ppw (fromIntegral ppwlen) (fromIntegral ops) (fromIntegral mem)

          case ret of
              0 -> Just <$> peekCAString pp
              _ -> pure Nothing

-- | Verifies that a certain password hash was constructed from the supplied password
pwhashStrVerify :: PasswordHash -> Text -> Bool
pwhashStrVerify (PasswordHash h) pw = unsafePerformIO $
  constByteStrings [TE.encodeUtf8 $ T.snoc h '\NUL', TE.encodeUtf8 pw] $ \[(ph, _), (ppw, ppwlen)] -> do
    res <- c_pwhash_str_verify ph ppw (fromIntegral ppwlen)
    pure (res == 0)

-- | Indicates whether a password needs to be rehashed, because the opslimit/memlimit parameters
-- used to hash the password are inconsistent with the supplied values.
-- Returns Nothing if the hash appears to be invalid.
-- Internally this function will always use the current DefaultAlgorithm and hence will give
-- undefined results if a different algorithm was used to hash the password.
needsRehash :: Opslimit -> Memlimit -> PasswordHash -> Maybe Bool
needsRehash (Opslimit ops) (Memlimit mem) (PasswordHash h) =
    unsafePerformIO $
        constByteStrings [TE.encodeUtf8 $ T.snoc h '\NUL'] $ \[(ph,_)] -> do
            res <- c_pwhash_str_needs_rehash ph (fromIntegral ops) (fromIntegral mem)
            pure $  if res == -1
                    then Nothing
                    else Just (res == 1)

-- | Derives a key of the specified length from a password using a salt according to the provided policy.
-- Since this function may cause a huge amount of memory to be allocated, it will return
-- Nothing if the allocation failed and on any other error.
pwhash :: Text -> Int -> Salt -> Policy -> Maybe ByteString
pwhash pw len (Salt salt) policy = do
  let (ops, mem, alg) = unpackPolicy policy

  let (e, hashed) =
        buildUnsafeByteString len $ \hbuf ->
          constByteStrings [TE.encodeUtf8 pw, salt] $ \[(ppw,ppwlen), (psalt,_)] ->
              c_pwhash
                    hbuf (fromIntegral len)
                    ppw (fromIntegral ppwlen)
                    psalt
                    (fromIntegral ops)
                    (fromIntegral mem)
                    (fromIntegral $ fromEnum alg)

  if e == -1
  then Nothing
  else Just hashed


-- | Smart constructor for opslimit
opslimit :: Algorithm -> Int -> Maybe Opslimit
opslimit alg x
  | Opslimit x < minOpslimit alg = Nothing
  | Opslimit x > maxOpslimit alg = Nothing
  | otherwise = Just (Opslimit x)

opslimitInteractive :: Algorithm -> Opslimit
opslimitInteractive DefaultAlgorithm = Opslimit (fromIntegral Bytes.pwhash_opslimit_interactive)
opslimitInteractive Argon2i13        = Opslimit (fromIntegral Bytes.pwhash_argon2i_opslimit_interactive)
opslimitInteractive Argon2id13       = Opslimit (fromIntegral Bytes.pwhash_argon2id_opslimit_interactive)

opslimitModerate :: Algorithm -> Opslimit
opslimitModerate DefaultAlgorithm   = Opslimit (fromIntegral Bytes.pwhash_opslimit_moderate)
opslimitModerate Argon2i13          = Opslimit (fromIntegral Bytes.pwhash_argon2i_opslimit_moderate)
opslimitModerate Argon2id13         = Opslimit (fromIntegral Bytes.pwhash_argon2id_opslimit_moderate)

opslimitSensitive :: Algorithm -> Opslimit
opslimitSensitive DefaultAlgorithm  = Opslimit (fromIntegral Bytes.pwhash_opslimit_sensitive)
opslimitSensitive Argon2i13         = Opslimit (fromIntegral Bytes.pwhash_argon2i_opslimit_sensitive)
opslimitSensitive Argon2id13        = Opslimit (fromIntegral Bytes.pwhash_argon2id_opslimit_sensitive)


-- | Smart constructor for memlimit
memlimit :: Algorithm -> Int -> Maybe Memlimit
memlimit alg x
  | Memlimit x < minMemlimit alg  = Nothing
  | Memlimit x > maxMemlimit alg= Nothing
  | otherwise = Just (Memlimit x)

memlimitInteractive :: Algorithm -> Memlimit
memlimitInteractive DefaultAlgorithm = Memlimit (fromIntegral Bytes.pwhash_memlimit_interactive)
memlimitInteractive Argon2i13        = Memlimit (fromIntegral Bytes.pwhash_argon2i_memlimit_interactive)
memlimitInteractive Argon2id13       = Memlimit (fromIntegral Bytes.pwhash_argon2id_memlimit_interactive)

memlimitModerate :: Algorithm -> Memlimit
memlimitModerate DefaultAlgorithm   = Memlimit (fromIntegral Bytes.pwhash_memlimit_moderate)
memlimitModerate Argon2i13          = Memlimit (fromIntegral Bytes.pwhash_argon2i_memlimit_moderate)
memlimitModerate Argon2id13         = Memlimit (fromIntegral Bytes.pwhash_argon2id_memlimit_moderate)

memlimitSensitive :: Algorithm -> Memlimit
memlimitSensitive DefaultAlgorithm  = Memlimit (fromIntegral Bytes.pwhash_memlimit_sensitive)
memlimitSensitive Argon2i13         = Memlimit (fromIntegral Bytes.pwhash_argon2i_memlimit_sensitive)
memlimitSensitive Argon2id13        = Memlimit (fromIntegral Bytes.pwhash_argon2id_memlimit_sensitive)

defaultAlgorithm :: Algorithm
defaultAlgorithm = DefaultAlgorithm


-- | Get raw C types from a policy, suitable for passing to FFI functions
unpackPolicy :: Policy -> (CULLong, CSize, CInt)
unpackPolicy (Policy ops mem alg) =
  ( fromIntegral (getOpslimit ops)
  , fromIntegral (getMemlimit mem)
  , algorithm alg
  )


{-
Fast policy suitable for low-powered devices

Takes approximately 0.1 seconds on a typical desktop computer
and requires 64 MiB of dedicated RAM
-}
interactivePolicy :: Policy
interactivePolicy = Policy (opslimitInteractive defaultAlgorithm)
                           (memlimitInteractive defaultAlgorithm)
                           defaultAlgorithm

{-|
Moderate policy with a balance of speed and security

Takes approximately 1 second on a typical desktop computer
and requires 256 MiB of dedicated RAM
-}
moderatePolicy :: Policy
moderatePolicy = Policy (opslimitModerate defaultAlgorithm)
                        (memlimitModerate defaultAlgorithm)
                        defaultAlgorithm

{-|
High-security policy designed to make attacking the password extremely expensive

Takes several seconds on a typical desktop computer
and requires 1024 MiB of dedicated RAM
-}
sensitivePolicy :: Policy
sensitivePolicy = Policy (opslimitSensitive defaultAlgorithm)
                         (memlimitSensitive defaultAlgorithm)
                         defaultAlgorithm


minOpslimit :: Algorithm -> Opslimit
minOpslimit DefaultAlgorithm = Opslimit $ fromIntegral Bytes.pwhash_opslimit_min
minOpslimit Argon2i13        = Opslimit $ fromIntegral Bytes.pwhash_argon2i_opslimit_min
minOpslimit Argon2id13       = Opslimit $ fromIntegral Bytes.pwhash_argon2id_opslimit_min

maxOpslimit :: Algorithm -> Opslimit
maxOpslimit DefaultAlgorithm = Opslimit $ fromIntegral Bytes.pwhash_opslimit_max
maxOpslimit Argon2i13        = Opslimit $ fromIntegral Bytes.pwhash_argon2i_opslimit_max
maxOpslimit Argon2id13       = Opslimit $ fromIntegral Bytes.pwhash_argon2id_opslimit_max

minMemlimit :: Algorithm -> Memlimit
minMemlimit DefaultAlgorithm = Memlimit $ fromIntegral Bytes.pwhash_memlimit_min
minMemlimit Argon2i13        = Memlimit $ fromIntegral Bytes.pwhash_argon2i_memlimit_min
minMemlimit Argon2id13       = Memlimit $ fromIntegral Bytes.pwhash_argon2id_memlimit_min

maxMemlimit :: Algorithm -> Memlimit
maxMemlimit DefaultAlgorithm = Memlimit $ fromIntegral Bytes.pwhash_memlimit_max
maxMemlimit Argon2i13        = Memlimit $ fromIntegral Bytes.pwhash_argon2i_memlimit_max
maxMemlimit Argon2id13       = Memlimit $ fromIntegral Bytes.pwhash_argon2id_memlimit_max

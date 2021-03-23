{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, DeriveGeneric, ForeignFunctionInterface #-}

-- |
-- Module      : Crypto.Saltine.Internal.Password
-- Copyright   : (c) Promethea Raschke 2018
--                   Max Amanshauser 2021
-- License     : MIT
-- Maintainer  : max@lambdalifting.org
-- Stability   : experimental
-- Portability : non-portable

module Crypto.Saltine.Internal.Password
  ( c_pwhash
  , c_pwhash_str
  , c_pwhash_str_verify
  , c_pwhash_str_needs_rehash

  , pwhash_alg_argon2i13
  , pwhash_alg_argon2id13
  , pwhash_alg_default
  , algorithm

  -- Default algorithm constants
  , pwhash_bytes_max
  , pwhash_bytes_min

  , pwhash_memlimit_interactive
  , pwhash_memlimit_moderate
  , pwhash_memlimit_sensitive
  , pwhash_memlimit_min
  , pwhash_memlimit_max

  , pwhash_opslimit_interactive
  , pwhash_opslimit_moderate
  , pwhash_opslimit_sensitive
  , pwhash_opslimit_min
  , pwhash_opslimit_max

  , pwhash_passwd_min
  , pwhash_passwd_max
  , pwhash_saltbytes
  , pwhash_strbytes
  , pwhash_strprefix

  -- Argon2i algorithm constants
  , pwhash_argon2i_bytes_max
  , pwhash_argon2i_bytes_min

  , pwhash_argon2i_memlimit_interactive
  , pwhash_argon2i_memlimit_moderate
  , pwhash_argon2i_memlimit_sensitive
  , pwhash_argon2i_memlimit_min
  , pwhash_argon2i_memlimit_max

  , pwhash_argon2i_opslimit_interactive
  , pwhash_argon2i_opslimit_moderate
  , pwhash_argon2i_opslimit_sensitive
  , pwhash_argon2i_opslimit_min
  , pwhash_argon2i_opslimit_max

  , pwhash_argon2i_passwd_min
  , pwhash_argon2i_passwd_max
  , pwhash_argon2i_saltbytes
  , pwhash_argon2i_strbytes
  , pwhash_argon2i_strprefix

  -- Argon2id algorithm constants
  , pwhash_argon2id_bytes_max
  , pwhash_argon2id_bytes_min

  , pwhash_argon2id_memlimit_interactive
  , pwhash_argon2id_memlimit_moderate
  , pwhash_argon2id_memlimit_sensitive
  , pwhash_argon2id_memlimit_min
  , pwhash_argon2id_memlimit_max

  , pwhash_argon2id_opslimit_interactive
  , pwhash_argon2id_opslimit_moderate
  , pwhash_argon2id_opslimit_sensitive
  , pwhash_argon2id_opslimit_min
  , pwhash_argon2id_opslimit_max

  , pwhash_argon2id_passwd_min
  , pwhash_argon2id_passwd_max
  , pwhash_argon2id_saltbytes
  , pwhash_argon2id_strbytes
  , pwhash_argon2id_strprefix

  , Salt(..)
  , PasswordHash(..)
  , Opslimit(..)
  , Memlimit(..)
  , Policy(..)
  , Algorithm(..)
  ) where

import Control.DeepSeq
import Crypto.Saltine.Class
import Crypto.Saltine.Internal.Util as U
import Data.ByteString              (ByteString)
import Data.Data                    (Data, Typeable)
import Data.Hashable                (Hashable)
import Data.Text                    (Text)
import GHC.Generics                 (Generic)
import Foreign.C
import Foreign.Ptr

import qualified Data.ByteString    as S
import qualified Data.Text.Encoding as DTE


-- | Salt for deriving keys from passwords
newtype Salt = Salt { unSalt :: ByteString } deriving (Ord, Data, Hashable, Typeable, Generic, NFData)
instance Eq Salt where
    Salt a == Salt b = U.compare a b
instance Show Salt where
    show = bin2hex . encode

instance IsEncoding Salt where
  decode v = if S.length v == pwhash_saltbytes
           then Just (Salt v)
           else Nothing
  {-# INLINE decode #-}
  encode (Salt v) = v
  {-# INLINE encode #-}

-- | Verification string for stored passwords
-- This hash contains only printable characters, hence we can just derive Show.
newtype PasswordHash = PasswordHash { unPasswordHash :: Text } deriving (Ord, Data, Hashable, Typeable, Generic, Show, NFData)
-- Constant time Eq instance, just in case.
instance Eq PasswordHash where
    PasswordHash a == PasswordHash b = U.compare (DTE.encodeUtf8 a) (DTE.encodeUtf8 b)

-- | Wrapper type for the operations used by password hashing
newtype Opslimit = Opslimit { getOpslimit :: Int } deriving (Eq, Ord, Data, Hashable, Typeable, Generic, Show, NFData)

-- | Wrapper type for the memory used by password hashing
newtype Memlimit = Memlimit { getMemlimit :: Int } deriving (Eq, Ord, Data, Hashable, Typeable, Generic, Show, NFData)

-- | Wrapper for opslimit, memlimit and algorithm
data Policy = Policy
  { opsPolicy :: Opslimit
  , memPolicy :: Memlimit
  , algPolicy :: Algorithm
  } deriving (Eq, Ord, Data, Typeable, Generic, Show)
instance Hashable Policy

-- | Algorithms known to Libsodium, as an enum datatype
data Algorithm
  = DefaultAlgorithm
  | Argon2i13
  | Argon2id13
  deriving (Eq, Enum, Ord, Show, Generic, Data, Typeable, Bounded)
instance Hashable Algorithm

algorithm :: Algorithm -> CInt
algorithm DefaultAlgorithm = fromIntegral pwhash_alg_default
algorithm Argon2i13        = fromIntegral pwhash_alg_argon2i13
algorithm Argon2id13       = fromIntegral pwhash_alg_argon2id13

-- | Lets libsodium pick a hashing algorithm
pwhash_alg_default :: Int
pwhash_alg_default = fromIntegral c_crypto_pwhash_alg_default
-- | version 1.3 of the Argon2i algorithm
pwhash_alg_argon2i13 :: Int
pwhash_alg_argon2i13 = fromIntegral c_crypto_pwhash_alg_argon2i13
-- | version 1.3 of the Argon2id algorithm
pwhash_alg_argon2id13 :: Int
pwhash_alg_argon2id13 = fromIntegral c_crypto_pwhash_alg_argon2id13

-- | Constants for the default algorithm
-- | Minimum output length for key derivation (16 (128 bits)).
pwhash_bytes_min :: Int
pwhash_bytes_min = fromIntegral c_crypto_pwhash_bytes_min
-- | Maximum output length for key derivation.
pwhash_bytes_max :: Int
pwhash_bytes_max = fromIntegral c_crypto_pwhash_bytes_max

-- | Minimum allowed memory limit for password hashing
pwhash_memlimit_min :: Int
pwhash_memlimit_min = fromIntegral c_crypto_pwhash_memlimit_min
-- | Maximum allowed memory limit for password hashing
pwhash_memlimit_max :: Int
pwhash_memlimit_max = fromIntegral c_crypto_pwhash_memlimit_max
-- | Constant for currently 64MB memory
pwhash_memlimit_interactive :: Int
pwhash_memlimit_interactive = fromIntegral c_crypto_pwhash_memlimit_interactive
-- | Constant for currently 256MB memory
pwhash_memlimit_moderate :: Int
pwhash_memlimit_moderate = fromIntegral c_crypto_pwhash_memlimit_moderate
-- | Constant for currently 1024MB memory
pwhash_memlimit_sensitive :: Int
pwhash_memlimit_sensitive = fromIntegral c_crypto_pwhash_memlimit_sensitive

-- | Minimum allowed number of computations for password hashing
pwhash_opslimit_min :: Int
pwhash_opslimit_min = fromIntegral c_crypto_pwhash_opslimit_min
-- | Maximum allowed number of computations for password hashing
pwhash_opslimit_max :: Int
pwhash_opslimit_max = fromIntegral c_crypto_pwhash_opslimit_max

-- | Constant for relatively fast hashing
pwhash_opslimit_interactive :: Int
pwhash_opslimit_interactive = fromIntegral c_crypto_pwhash_opslimit_interactive
-- | Constant for moderately fast hashing
pwhash_opslimit_moderate :: Int
pwhash_opslimit_moderate = fromIntegral c_crypto_pwhash_opslimit_moderate
-- | Constant for relatively slow hashing
pwhash_opslimit_sensitive :: Int
pwhash_opslimit_sensitive = fromIntegral c_crypto_pwhash_opslimit_sensitive

-- | Minimum number of characters in password for key derivation
pwhash_passwd_min :: Int
pwhash_passwd_min = fromIntegral c_crypto_pwhash_passwd_min
-- | Maximum number of characters in password for key derivation
pwhash_passwd_max :: Int
pwhash_passwd_max = fromIntegral c_crypto_pwhash_passwd_max

-- | Size of salt
pwhash_saltbytes :: Int
pwhash_saltbytes = fromIntegral c_crypto_pwhash_saltbytes
-- | (Maximum) size of password hashing output
pwhash_strbytes :: Int
pwhash_strbytes = fromIntegral c_crypto_pwhash_strbytes
-- string that hashes with this algorithm are prefixed with
pwhash_strprefix :: Int
pwhash_strprefix = fromIntegral c_crypto_pwhash_strprefix


-- | Constants for Argon2ID
-- | Minimum output length for key derivation (= 16 (128 bits)).
pwhash_argon2id_bytes_min :: Int
pwhash_argon2id_bytes_min = fromIntegral c_crypto_pwhash_argon2id_bytes_min
-- | Maximum output length for key derivation.
pwhash_argon2id_bytes_max :: Int
pwhash_argon2id_bytes_max = fromIntegral c_crypto_pwhash_argon2id_bytes_max

-- | Minimum allowed memory limit for password hashing
pwhash_argon2id_memlimit_min :: Int
pwhash_argon2id_memlimit_min = fromIntegral c_crypto_pwhash_argon2id_memlimit_min
-- | Maximum allowed memory limit for password hashing
pwhash_argon2id_memlimit_max :: Int
pwhash_argon2id_memlimit_max = fromIntegral c_crypto_pwhash_argon2id_memlimit_max
-- | Constant for currently 64MB memory
pwhash_argon2id_memlimit_interactive :: Int
pwhash_argon2id_memlimit_interactive = fromIntegral c_crypto_pwhash_argon2id_memlimit_interactive
-- | Constant for currently 256MB memory
pwhash_argon2id_memlimit_moderate :: Int
pwhash_argon2id_memlimit_moderate = fromIntegral c_crypto_pwhash_argon2id_memlimit_moderate
-- | Constant for currently 1024MB memory
pwhash_argon2id_memlimit_sensitive :: Int
pwhash_argon2id_memlimit_sensitive = fromIntegral c_crypto_pwhash_argon2id_memlimit_sensitive

-- | Minimum allowed number of computations for password hashing
pwhash_argon2id_opslimit_min :: Int
pwhash_argon2id_opslimit_min = fromIntegral c_crypto_pwhash_argon2id_opslimit_min
-- | Maximum allowed number of computations for password hashing
pwhash_argon2id_opslimit_max :: Int
pwhash_argon2id_opslimit_max = fromIntegral c_crypto_pwhash_argon2id_opslimit_max

-- | Constant for relatively fast hashing
pwhash_argon2id_opslimit_interactive :: Int
pwhash_argon2id_opslimit_interactive = fromIntegral c_crypto_pwhash_argon2id_opslimit_interactive
-- | Constant for moderately fast hashing
pwhash_argon2id_opslimit_moderate :: Int
pwhash_argon2id_opslimit_moderate = fromIntegral c_crypto_pwhash_argon2id_opslimit_moderate
-- | Constant for relatively slow hashing
pwhash_argon2id_opslimit_sensitive :: Int
pwhash_argon2id_opslimit_sensitive = fromIntegral c_crypto_pwhash_argon2id_opslimit_sensitive

-- | Minimum number of characters in password for key derivation
pwhash_argon2id_passwd_min :: Int
pwhash_argon2id_passwd_min = fromIntegral c_crypto_pwhash_argon2id_passwd_min
-- | Maximum number of characters in password for key derivation
pwhash_argon2id_passwd_max :: Int
pwhash_argon2id_passwd_max = fromIntegral c_crypto_pwhash_argon2id_passwd_max

-- | Size of salt
pwhash_argon2id_saltbytes :: Int
pwhash_argon2id_saltbytes = fromIntegral c_crypto_pwhash_argon2id_saltbytes
-- | (Maximum) size of password hashing output
pwhash_argon2id_strbytes :: Int
pwhash_argon2id_strbytes = fromIntegral c_crypto_pwhash_argon2id_strbytes
-- string that hashes with this algorithm are prefixed with
pwhash_argon2id_strprefix :: Int
pwhash_argon2id_strprefix = fromIntegral c_crypto_pwhash_argon2id_strprefix

-- | Constants for ARGON2I
-- | Minimum output length for key derivation (= 16 (128 bits)).
pwhash_argon2i_bytes_min :: Int
pwhash_argon2i_bytes_min = fromIntegral c_crypto_pwhash_argon2i_bytes_min
-- | Maximum output length for key derivation.
pwhash_argon2i_bytes_max :: Int
pwhash_argon2i_bytes_max = fromIntegral c_crypto_pwhash_argon2i_bytes_max

-- | Minimum allowed memory limit for password hashing
pwhash_argon2i_memlimit_min :: Int
pwhash_argon2i_memlimit_min = fromIntegral c_crypto_pwhash_argon2i_memlimit_min
-- | Maximum allowed memory limit for password hashing
pwhash_argon2i_memlimit_max :: Int
pwhash_argon2i_memlimit_max = fromIntegral c_crypto_pwhash_argon2i_memlimit_max
-- | Constant for currently 64MB memory
pwhash_argon2i_memlimit_interactive :: Int
pwhash_argon2i_memlimit_interactive = fromIntegral c_crypto_pwhash_argon2i_memlimit_interactive
-- | Constant for currently 256MB memory
pwhash_argon2i_memlimit_moderate :: Int
pwhash_argon2i_memlimit_moderate = fromIntegral c_crypto_pwhash_argon2i_memlimit_moderate
-- | Constant for currently 1024MB memory
pwhash_argon2i_memlimit_sensitive :: Int
pwhash_argon2i_memlimit_sensitive = fromIntegral c_crypto_pwhash_argon2i_memlimit_sensitive

-- | Minimum allowed number of computations for password hashing
pwhash_argon2i_opslimit_min :: Int
pwhash_argon2i_opslimit_min = fromIntegral c_crypto_pwhash_argon2i_opslimit_min
-- | Maximum allowed number of computations for password hashing
pwhash_argon2i_opslimit_max :: Int
pwhash_argon2i_opslimit_max = fromIntegral c_crypto_pwhash_argon2i_opslimit_max

-- | Constant for relatively fast hashing
pwhash_argon2i_opslimit_interactive :: Int
pwhash_argon2i_opslimit_interactive = fromIntegral c_crypto_pwhash_argon2i_opslimit_interactive
-- | Constant for moderately fast hashing
pwhash_argon2i_opslimit_moderate :: Int
pwhash_argon2i_opslimit_moderate = fromIntegral c_crypto_pwhash_argon2i_opslimit_moderate
-- | Constant for relatively slow hashing
pwhash_argon2i_opslimit_sensitive :: Int
pwhash_argon2i_opslimit_sensitive = fromIntegral c_crypto_pwhash_argon2i_opslimit_sensitive

-- | Minimum number of characters in password for key derivation
pwhash_argon2i_passwd_min :: Int
pwhash_argon2i_passwd_min = fromIntegral c_crypto_pwhash_argon2i_passwd_min
-- | Maximum number of characters in password for key derivation
pwhash_argon2i_passwd_max :: Int
pwhash_argon2i_passwd_max = fromIntegral c_crypto_pwhash_argon2i_passwd_max

-- | Size of salt
pwhash_argon2i_saltbytes :: Int
pwhash_argon2i_saltbytes = fromIntegral c_crypto_pwhash_argon2i_saltbytes
-- | (Maximum) size of password hashing output
pwhash_argon2i_strbytes :: Int
pwhash_argon2i_strbytes = fromIntegral c_crypto_pwhash_argon2i_strbytes
-- string that hashes with this algorithm are prefixed with
pwhash_argon2i_strprefix :: Int
pwhash_argon2i_strprefix = fromIntegral c_crypto_pwhash_argon2i_strprefix



foreign import ccall "crypto_pwhash"
  c_pwhash
        :: Ptr CChar
        -- ^ Derived key output buffer
        -> CULLong
        -- ^ Derived key length
        -> Ptr CChar
        -- ^ Password input buffer
        -> CULLong
        -- ^ Password length
        -> Ptr CChar
        -- ^ Salt input buffer
        -> CULLong
        -- ^ Operation limit
        -> CSize
        -- ^ Memory usage limit
        -> CInt
        -- ^ Algorithm
        -> IO CInt

foreign import ccall "crypto_pwhash_str"
  c_pwhash_str
        :: Ptr CChar
        -- ^ Hashed password output buffer
        -> Ptr CChar
        -- ^ Password input buffer
        -> CULLong
        -- ^ Password length
        -> CULLong
        -- ^ Operation limit
        -> CSize
        -- ^ Memory usage limit
        -> IO CInt

foreign import ccall "crypto_pwhash_str_verify"
  c_pwhash_str_verify
        :: Ptr CChar
        -- ^ Hashed password input buffer
        -> Ptr CChar
        -- ^ Password input buffer
        -> CULLong
        -- ^ Password length
        -> IO CInt

foreign import ccall "crypto_pwhash_str_needs_rehash"
  c_pwhash_str_needs_rehash
        :: Ptr CChar
        -- ^ Hashed password input buffer
        -> CULLong
        -- ^ Operation limit
        -> CSize
        -- ^ Memory usage limit
        -> IO CInt

foreign import ccall "crypto_pwhash_alg_argon2id13"
  c_crypto_pwhash_alg_argon2id13 :: CSize

foreign import ccall "crypto_pwhash_alg_argon2i13"
  c_crypto_pwhash_alg_argon2i13 :: CSize

foreign import ccall "crypto_pwhash_alg_default"
  c_crypto_pwhash_alg_default :: CSize

-- Constants for the default algorithm
foreign import ccall "crypto_pwhash_bytes_min"
  c_crypto_pwhash_bytes_min :: CSize

foreign import ccall "crypto_pwhash_bytes_max"
  c_crypto_pwhash_bytes_max :: CSize

foreign import ccall "crypto_pwhash_memlimit_min"
  c_crypto_pwhash_memlimit_min :: CSize

foreign import ccall "crypto_pwhash_memlimit_max"
  c_crypto_pwhash_memlimit_max :: CSize

foreign import ccall "crypto_pwhash_memlimit_interactive"
  c_crypto_pwhash_memlimit_interactive :: CSize

foreign import ccall "crypto_pwhash_memlimit_moderate"
  c_crypto_pwhash_memlimit_moderate :: CSize

foreign import ccall "crypto_pwhash_memlimit_sensitive"
  c_crypto_pwhash_memlimit_sensitive :: CSize

foreign import ccall "crypto_pwhash_opslimit_min"
  c_crypto_pwhash_opslimit_min :: CSize

foreign import ccall "crypto_pwhash_opslimit_max"
  c_crypto_pwhash_opslimit_max :: CSize

foreign import ccall "crypto_pwhash_opslimit_interactive"
  c_crypto_pwhash_opslimit_interactive :: CSize

foreign import ccall "crypto_pwhash_opslimit_moderate"
  c_crypto_pwhash_opslimit_moderate :: CSize

foreign import ccall "crypto_pwhash_opslimit_sensitive"
  c_crypto_pwhash_opslimit_sensitive :: CSize

foreign import ccall "crypto_pwhash_passwd_min"
  c_crypto_pwhash_passwd_min :: CSize

foreign import ccall "crypto_pwhash_passwd_max"
  c_crypto_pwhash_passwd_max :: CSize

foreign import ccall "crypto_pwhash_saltbytes"
  c_crypto_pwhash_saltbytes :: CSize

foreign import ccall "crypto_pwhash_strbytes"
  c_crypto_pwhash_strbytes :: CSize

foreign import ccall "crypto_pwhash_strprefix"
  c_crypto_pwhash_strprefix :: CSize

-- Constants for ARGON2ID (currently default)
foreign import ccall "crypto_pwhash_argon2id_bytes_min"
  c_crypto_pwhash_argon2id_bytes_min :: CSize

foreign import ccall "crypto_pwhash_argon2id_bytes_max"
  c_crypto_pwhash_argon2id_bytes_max :: CSize

foreign import ccall "crypto_pwhash_argon2id_memlimit_min"
  c_crypto_pwhash_argon2id_memlimit_min :: CSize

foreign import ccall "crypto_pwhash_argon2id_memlimit_max"
  c_crypto_pwhash_argon2id_memlimit_max :: CSize

foreign import ccall "crypto_pwhash_argon2id_memlimit_interactive"
  c_crypto_pwhash_argon2id_memlimit_interactive :: CSize

foreign import ccall "crypto_pwhash_argon2id_memlimit_moderate"
  c_crypto_pwhash_argon2id_memlimit_moderate :: CSize

foreign import ccall "crypto_pwhash_argon2id_memlimit_sensitive"
  c_crypto_pwhash_argon2id_memlimit_sensitive :: CSize

foreign import ccall "crypto_pwhash_argon2id_opslimit_min"
  c_crypto_pwhash_argon2id_opslimit_min :: CSize

foreign import ccall "crypto_pwhash_argon2id_opslimit_max"
  c_crypto_pwhash_argon2id_opslimit_max :: CSize

foreign import ccall "crypto_pwhash_argon2id_opslimit_interactive"
  c_crypto_pwhash_argon2id_opslimit_interactive :: CSize

foreign import ccall "crypto_pwhash_argon2id_opslimit_moderate"
  c_crypto_pwhash_argon2id_opslimit_moderate :: CSize

foreign import ccall "crypto_pwhash_argon2id_opslimit_sensitive"
  c_crypto_pwhash_argon2id_opslimit_sensitive :: CSize

foreign import ccall "crypto_pwhash_argon2id_passwd_min"
  c_crypto_pwhash_argon2id_passwd_min :: CSize

foreign import ccall "crypto_pwhash_argon2id_passwd_max"
  c_crypto_pwhash_argon2id_passwd_max :: CSize

foreign import ccall "crypto_pwhash_argon2id_saltbytes"
  c_crypto_pwhash_argon2id_saltbytes :: CSize

foreign import ccall "crypto_pwhash_argon2id_strbytes"
  c_crypto_pwhash_argon2id_strbytes :: CSize

foreign import ccall "crypto_pwhash_argon2id_strprefix"
  c_crypto_pwhash_argon2id_strprefix :: CSize


-- Constants for ARGON2I
foreign import ccall "crypto_pwhash_argon2i_bytes_min"
  c_crypto_pwhash_argon2i_bytes_min :: CSize

foreign import ccall "crypto_pwhash_argon2i_bytes_max"
  c_crypto_pwhash_argon2i_bytes_max :: CSize

foreign import ccall "crypto_pwhash_argon2i_memlimit_min"
  c_crypto_pwhash_argon2i_memlimit_min :: CSize

foreign import ccall "crypto_pwhash_argon2i_memlimit_max"
  c_crypto_pwhash_argon2i_memlimit_max :: CSize

foreign import ccall "crypto_pwhash_argon2i_memlimit_interactive"
  c_crypto_pwhash_argon2i_memlimit_interactive :: CSize

foreign import ccall "crypto_pwhash_argon2i_memlimit_moderate"
  c_crypto_pwhash_argon2i_memlimit_moderate :: CSize

foreign import ccall "crypto_pwhash_argon2i_memlimit_sensitive"
  c_crypto_pwhash_argon2i_memlimit_sensitive :: CSize

foreign import ccall "crypto_pwhash_argon2i_opslimit_min"
  c_crypto_pwhash_argon2i_opslimit_min :: CSize

foreign import ccall "crypto_pwhash_argon2i_opslimit_max"
  c_crypto_pwhash_argon2i_opslimit_max :: CSize

foreign import ccall "crypto_pwhash_argon2i_opslimit_interactive"
  c_crypto_pwhash_argon2i_opslimit_interactive :: CSize

foreign import ccall "crypto_pwhash_argon2i_opslimit_moderate"
  c_crypto_pwhash_argon2i_opslimit_moderate :: CSize

foreign import ccall "crypto_pwhash_argon2i_opslimit_sensitive"
  c_crypto_pwhash_argon2i_opslimit_sensitive :: CSize

foreign import ccall "crypto_pwhash_argon2i_passwd_min"
  c_crypto_pwhash_argon2i_passwd_min :: CSize

foreign import ccall "crypto_pwhash_argon2i_passwd_max"
  c_crypto_pwhash_argon2i_passwd_max :: CSize

foreign import ccall "crypto_pwhash_argon2i_saltbytes"
  c_crypto_pwhash_argon2i_saltbytes :: CSize

foreign import ccall "crypto_pwhash_argon2i_strbytes"
  c_crypto_pwhash_argon2i_strbytes :: CSize

foreign import ccall "crypto_pwhash_argon2i_strprefix"
  c_crypto_pwhash_argon2i_strprefix :: CSize

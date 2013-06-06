{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Saltine (
  optimize,
  module Crypto.Saltine.Core.SecretBox
  ) where

import Foreign.C

import Data.Data
import Control.Exception

import Crypto.Saltine.Core.SecretBox

{- Notes:

* Check thread safety of `randombytes_random`, `randombytes_uniform`,
  `randombytes_buf`, `randombytes_close`, `crypto_sign_keypair`, and
  `crypto_box_keypair`.

* Consider a monadic interface for using the `randombytes_*` interface
  so as to ensure `close` is called and that it is used in a threadsafe
  manner.

* Keys are insecurely read from disk---they may be copied and then
  paged back to disk. Use at your own risk.

-}

{- Todo:

* Refactor secretbox/secretboxOpen

-}

data SaltineException = OptimizationFailure | UnknownFailure
                    deriving (Typeable, Show)
instance Exception SaltineException

foreign import ccall "sodium_init" c_sodiumInit :: IO CInt

-- | Runs Sodiums's optimizer. This has no semantic effect, but both
-- may boost the speed of Sodium after running it. It is recommended
-- in production environments. It is, however, NOT thread-safe so no
-- other Sodium functions should be called until it successfully
-- returns.
optimize :: IO ()
optimize = do
  err <- c_sodiumInit
  case err of
    0  -> -- everything went well
      return ()
    1  -> -- already initialized, we're good
      return ()
    -1 -> -- some kind of failure
      throw OptimizationFailure
    _  -> -- what?
      throw UnknownFailure

-- Random Things

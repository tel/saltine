{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TypeFamilies             #-}

module Crypto.Saltine (
  optimize,
  module Crypto.Saltine.Core.SecretBox
  ) where

import Foreign.C
import Crypto.Saltine.Core.SecretBox

-- | Runs Sodiums's optimizer. This has no semantic effect, but both
-- may boost the speed of Sodium after running it. It is recommended
-- in production environments. It is, however, NOT thread-safe so no
-- other Sodium functions should be called until it successfully
-- returns.
optimize :: IO ()
optimize = do
  err <- c_sodiumInit
  case err of
    0 -> -- everything went well
      return ()
    1 -> -- already initialized, we're good
      return ()
    _ -> -- some kind of failure
      error "Crypto.Saltine.optimize"

foreign import ccall "sodium_init" c_sodiumInit :: IO CInt

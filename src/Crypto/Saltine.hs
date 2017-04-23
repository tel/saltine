{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TypeFamilies             #-}

module Crypto.Saltine (
  optimize,
  module Crypto.Saltine.Core.SecretBox
  ) where

import Foreign.C
import Crypto.Saltine.Core.SecretBox

-- | Runs Sodiums's initialization routine. This should be called before
-- using any other function. It is thread-safe since libsodium 1.0.11,
-- but not before.
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

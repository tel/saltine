{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TypeFamilies             #-}

module Crypto.Saltine (
  sodiumInit
  ) where

import Foreign.C

-- | Runs Sodiums's initialization routine. This must be called before
-- using any other function. It is thread-safe since libsodium 1.0.11.
sodiumInit :: IO ()
sodiumInit = do
  err <- c_sodiumInit
  case err of
    0 -> -- everything went well
      return ()
    1 -> -- already initialized, we're good
      return ()
    _ -> -- some kind of failure
      error "Crypto.Saltine.sodiumInit"

foreign import ccall "sodium_init" c_sodiumInit :: IO CInt

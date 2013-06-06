-- |
-- Module      : Crypto.Saltine.Util
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
-- 
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Utilities for using any of Saltine: "Crypto.Saltine.Util"
-- 
-- "Crypto.Saltine.Util" is a utility module which contains functions
-- useful for using Saltine but not specific to any particular
-- cryptographic modality.
module Crypto.Saltine.Util (
  optimize, ashex,
  module Crypto.Saltine.Types,
  module Crypto.Saltine.Class
  ) where

import Foreign.C
import Crypto.Saltine.Internal.Util
import Crypto.Saltine.Types
import Crypto.Saltine.Class

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
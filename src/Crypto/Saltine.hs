{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Saltine (
  module Crypto.Saltine.Core.SecretBox,
  module Crypto.Saltine.Util
  ) where

import Crypto.Saltine.Util
import Crypto.Saltine.Core.SecretBox

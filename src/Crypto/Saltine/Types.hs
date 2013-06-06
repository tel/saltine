-- |
-- Module      : Crypto.Saltine.Core.Auth
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
-- 
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Convenience types and encodings
module Crypto.Saltine.Types (
  Message (..)
  ) where

import Crypto.Saltine.Internal.Util
import Crypto.Saltine.Class

import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

import Control.Monad

-- | A container for Text messages.
newtype Message = Message { readMessage :: T.Text } deriving (Eq, Show, Ord)

instance IsEncoding Message where
  encode = encode . TE.encodeUtf8 . readMessage
  decode = fmap Message . hush . TE.decodeUtf8' <=< decode


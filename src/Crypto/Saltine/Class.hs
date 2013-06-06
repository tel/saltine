-- |
-- Module      : Crypto.Saltine.Class
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
-- 
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Saltine type classes
module Crypto.Saltine.Class (
  IsEncoding (..)
  ) where

import Data.Profunctor
import Data.Word
import qualified Data.Vector.Storable as V
import Control.Applicative

-- | Class for all keys and nonces in Saltine which have a
-- representation as 'V.Vector' of 'Word8'. 'encoded' is a 'Prism' of
-- type @Prism' (V.Vector Word8) a@ compatible with "Control.Lens" and
-- is automatically deduced.
class IsEncoding a where
  encode  :: a -> V.Vector Word8
  decode  :: V.Vector Word8 -> Maybe a
  encoded :: (Choice p, Applicative f)
             => p a (f a) -> p (V.Vector Word8) (f (V.Vector Word8))
  encoded = prism' encode decode
  {-# INLINE encoded #-}


-- Copied over from Control.Lens

prism' :: (Applicative f, Choice p) =>
          (a1 -> a) -> (a -> Maybe a2) -> p a2 (f a1) -> p a (f a)
prism' bs sma = prism bs (\s -> maybe (Left s) Right (sma s))
{-# INLINE prism' #-}

prism :: (Applicative f, Choice p) =>
         (a2 -> a1) -> (a -> Either a1 a3) -> p a3 (f a2) -> p a (f a1)
prism bt seta = dimap seta (either pure (fmap bt)) . right'
{-# INLINE prism #-}
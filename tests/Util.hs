{-# LANGUAGE OverloadedStrings #-}

module Util where

import Test.QuickCheck

import Data.Word
import qualified Data.ByteString as S
import qualified Data.Vector.Storable as V

import Control.Applicative

fromBS :: S.ByteString -> V.Vector Word8
fromBS = V.fromList . S.unpack

toBS ::  V.Vector Word8 -> S.ByteString
toBS = S.pack . V.toList

newtype Message = Message S.ByteString
                deriving (Show)

instance Arbitrary Message where
  arbitrary = Message . S.intercalate " " <$> listOf (oneof [
    return "word",
    return "other word"
    ])
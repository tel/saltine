module Util where

import Test.QuickCheck

import Crypto.Saltine.Class

import Data.Word
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8

import Control.Applicative

perturb :: IsEncoding a => a -> a
perturb a = case decode (S.reverse (encode a)) of
  Just x -> x
  Nothing -> error "Util.perturb"

newtype Message = Message S.ByteString deriving (Show)

instance Arbitrary Message where
  arbitrary = Message . S.intercalate (S8.pack " ") <$> listOf (oneof [
    return (S8.pack "word"),
    return (S8.pack "other word")
    ])
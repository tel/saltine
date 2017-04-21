module Util where

import           Crypto.Saltine.Class

import           Control.Applicative
import           Control.Monad           (replicateM)
import qualified Data.ByteString       as S
import qualified Data.ByteString.Char8 as S8
import           Data.Maybe              (fromMaybe)
import           Test.QuickCheck


perturb :: IsEncoding a => a -> a
perturb a = fromMaybe (error "Util.perturb")
                      (decode (S.reverse (encode a)))

newtype ByteString32 = ByteString32 S.ByteString deriving (Show)

instance Arbitrary ByteString32 where
  arbitrary = ByteString32 . S.pack <$> replicateM 32 arbitrary

newtype Message = Message S.ByteString deriving (Show)

instance Arbitrary Message where
  arbitrary = Message . S.intercalate (S8.pack " ") <$> listOf (oneof [
    return (S8.pack "word"),
    return (S8.pack "other word")
    ])

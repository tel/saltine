{-# LANGUAGE OverloadedStrings #-}

module UtilProperties (
  testUtils
  ) where

import Test.Framework.Providers.QuickCheck2
import Test.Framework
import Test.QuickCheck
import Util

import qualified Crypto.Saltine.Internal.Util as U

-- | Testing the comparison of keys
keyEquality :: ByteString32 -> Property
keyEquality k@(ByteString32 bs1) = k === k .&. U.compare bs1 bs1

keyInequality :: ByteString32 -> ByteString32 -> Property
keyInequality k1@(ByteString32 bs1) k2@(ByteString32 bs2) =
    k1 /= k2 ==> not $ U.compare bs1 bs2


testUtils :: Test
testUtils = buildTest $ do
  return $ testGroup "...Utils" [
    testProperty "ByteString equality"      keyEquality,
    testProperty "ByteString inequality"    keyInequality
    ]

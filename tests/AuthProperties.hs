{-# LANGUAGE OverloadedStrings #-}

module AuthProperties (
  testAuth
  ) where

import Util

import qualified Crypto.Saltine.Internal.Auth as A

import Test.Framework.Providers.QuickCheck2
import Test.Framework

testAuth :: Test
testAuth = buildTest $ do
  k <- A.newKey
  return $ testGroup "...Internal.Auth" [

    testProperty "Authenticates message"
    $ \(Message bs) -> let m = fromBS bs in A.verify k m (A.auth k m) == True

    ]
{-# LANGUAGE OverloadedStrings #-}

module OneTimeAuthProperties (
  testOneTimeAuth
  ) where

import Util

import Crypto.Saltine.Core.OneTimeAuth

import Test.Framework.Providers.QuickCheck2
import Test.Framework

testOneTimeAuth :: Test
testOneTimeAuth = buildTest $ do
  k <- newKey
  return $ testGroup "...Internal.Auth" [

    testProperty "Authenticates message"
    $ \(Message bs) -> let m = fromBS bs in verify k (auth k m) m == True

    ]
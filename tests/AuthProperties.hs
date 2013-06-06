{-# LANGUAGE OverloadedStrings #-}

module AuthProperties (
  testAuth
  ) where

import Util

import Crypto.Saltine.Core.Auth

import Test.Framework.Providers.QuickCheck2
import Test.Framework

testAuth :: Test
testAuth = buildTest $ do
  k <- newKey
  return $ testGroup "...Internal.Auth" [

    testProperty "Authenticates message"
    $ \(Message bs) -> let m = fromBS bs in verify k (auth k m) m  == True

    ]
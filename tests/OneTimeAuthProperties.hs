{-# LANGUAGE OverloadedStrings #-}

module OneTimeAuthProperties (
  testOneTimeAuth
  ) where

import Util

import qualified Crypto.Saltine.Internal.OneTimeAuth as O

import Test.Framework.Providers.QuickCheck2
import Test.Framework

testOneTimeAuth :: Test
testOneTimeAuth = buildTest $ do
  k <- O.newKey
  return $ testGroup "...Internal.Auth" [

    testProperty "Authenticates message"
    $ \(Message bs) -> let m = fromBS bs in O.verify k m (O.auth k m) == True

    ]
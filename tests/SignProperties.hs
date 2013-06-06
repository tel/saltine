{-# LANGUAGE OverloadedStrings #-}

module SignProperties (
  testSign
  ) where

import Util

import qualified Crypto.Saltine.Internal.Sign as S

import qualified Data.Vector.Storable as V

import Test.Framework.Providers.QuickCheck2
import Test.Framework
import Test.QuickCheck

testSign :: Test
testSign = buildTest $ do
  (sk1,  pk1) <- S.newKeypair
  (_sk2, pk2) <- S.newKeypair

  return $ testGroup "...Internal.Sign" [

    testProperty "Verifies signed message"
    $ \(Message bs) -> let m = fromBS bs
                       in S.signOpen pk1 (S.sign sk1 m) == Just m,

    testProperty "Signed message longer than message"
    $ \(Message bs) -> let m  = fromBS bs
                           sm = S.sign sk1 m
                       in V.length sm >= V.length m,

    testProperty "Rejects message with mismatched key"
    $ \(Message bs) -> let m = fromBS bs
                       in V.length m > 0
                           ==> S.signOpen pk2 (S.sign sk1 m) == Nothing

    ]
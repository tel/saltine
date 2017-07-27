{-# LANGUAGE OverloadedStrings #-}

module SignProperties (
  testSign
  ) where

import           Util
import           Crypto.Saltine.Core.Sign

import qualified Data.ByteString                      as S
import           Test.Framework.Providers.QuickCheck2
import           Test.Framework
import           Test.QuickCheck

testSign :: Test
testSign = buildTest $ do
  (sk1,  pk1) <- newKeypair
  (_sk2, pk2) <- newKeypair

  return $ testGroup "...Internal.Sign" [

    testProperty "Verifies signed message"
    $ \(Message bs) -> signOpen pk1 (sign sk1 bs) == Just bs,

    testProperty "Verifies signed message w/ detached signature"
    $ \(Message bs) -> signVerifyDetached pk1 (signDetached sk1 bs) bs,

    testProperty "Signed message longer than message"
    $ \(Message bs) -> S.length (sign sk1 bs) >= S.length bs,

    testProperty "Rejects message with mismatched key"
    $ \(Message bs) -> not (S.null bs) ==>
                         signOpen pk2 (sign sk1 bs) == Nothing,

    testProperty "Rejects message with mismatched key w/ detached signature"
    $ \(Message bs) -> not (S.null bs) ==>
                         not (signVerifyDetached pk2 (sign sk1 bs) bs)

    ]

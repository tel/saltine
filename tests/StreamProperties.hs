{-# LANGUAGE OverloadedStrings #-}

module StreamProperties (
  testStream
  ) where

import           Util
import           Crypto.Saltine.Core.Stream

import qualified Data.ByteString                      as S
import           Test.Framework.Providers.QuickCheck2
import           Test.Framework
import           Test.QuickCheck

testStream :: Test
testStream = buildTest $ do
  k <- newKey
  n <- newNonce
  return $ testGroup "...Internal.Stream" [

    testProperty "Stream is apropriately sized"
    $ \len -> (len > 0 && len < 200)
              ==> S.length (stream k n len) == len,

    testProperty "xor munges input"
    $ \(ByteString32 bs) ->     -- ByteString32 so we don't fail the test by pure chance, e.g. in case of 1-byte bytestrings
        xor k n bs /= bs,

    testProperty "xor is involutive"
    $ \(Message bs) -> xor k n (xor k n bs) == bs

    ]

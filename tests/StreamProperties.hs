{-# LANGUAGE OverloadedStrings #-}

module StreamProperties (
  testStream
  ) where

import Util

import qualified Crypto.Saltine.Internal.Stream as S

import qualified Data.Vector.Storable as V

import Test.Framework.Providers.QuickCheck2
import Test.Framework
import Test.QuickCheck

-- Length of output stream
-- Involutivity of xor

testStream :: Test
testStream = buildTest $ do
  k <- S.newKey
  n <- S.newNonce
  return $ testGroup "...Internal.Stream" [

    testProperty "Stream is apropriately sized"
    $ \len -> (len > 0 && len < 200)
              ==> V.length (S.stream k n len) == len,

    testProperty "xor munges input"
    $ \(Message bs) -> not (V.null $ fromBS bs)
                       ==> toBS (S.xor k n $ fromBS bs) /= bs,

    testProperty "xor is involutive"
    $ \(Message bs) -> toBS (S.xor k n $ S.xor k n $ fromBS bs) == bs
    
    ]
    
       

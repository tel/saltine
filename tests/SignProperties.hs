{-# LANGUAGE OverloadedStrings #-}

module SignProperties (
  testSign
  ) where

import           Util
import           Crypto.Saltine.Class

import           Crypto.Saltine.Core.Sign
import           Crypto.Saltine.Internal.Sign
import qualified Crypto.Saltine.Core.Box              as Box
import           Crypto.Saltine.Core.ScalarMult       ()
import           Crypto.Saltine.Internal.ScalarMult
import qualified Data.ByteString                      as S
import           Data.Maybe                           (fromJust)
import           Test.Framework.Providers.QuickCheck2
import           Test.Framework
import           Test.QuickCheck

testSign :: Test
testSign = buildTest $ do
  kp1 <- newKeypair
  let sk1 = secretKey kp1
  let pk1 = publicKey kp1
  kp2 <- newKeypair
  let sk2 = secretKey kp2
  let pk2 = publicKey kp2
  n <- Box.newNonce

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
                         not (signVerifyDetached pk2 (signDetached sk1 bs) bs),

    testProperty "Ed25515 -> Curve25519 conversion produces valid keypairs"
    $ \(Message bs) ->
        let p1 = fromJust . decode . unGE . fromJust $ signPublicKeyToScalarMult pk1
            s1 = fromJust . decode . unSc . fromJust $ signSecretKeyToScalarMult sk1

            p2 = fromJust . decode . unGE . fromJust $ signPublicKeyToScalarMult pk2
            s2 = fromJust . decode . unSc . fromJust $ signSecretKeyToScalarMult sk2

        in  (Box.boxOpen p2 s1 n (Box.box p1 s2 n bs)) == Just bs
    ]

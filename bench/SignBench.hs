module SignBench (benchSign, signEnv) where

import Criterion.Main

import Control.Monad
import Control.DeepSeq
import Control.Exception
import Data.ByteString as BS

import Crypto.Saltine.Core.Sign as S

import BenchUtils

signEnv :: IO Keypair
signEnv = newKeypair

benchSign :: Keypair -> Benchmark
benchSign alice = do
  let sign :: ByteString -> ByteString
      sign = S.sign (fst alice)

      verify :: ByteString -> Bool
      verify message =
        let signed = sign message
        in case S.signOpen (snd alice) signed of
          Nothing -> False
          Just ms -> True

      signDetached               = S.signDetached       (fst alice)
      signVerifyDetached message = S.signVerifyDetached (snd alice) (signDetached message)
  bgroup "Sign"
    [ bench "newKeypair" $ nfIO newKeypair
    , bgroup "sign"
      [ bench "128 B" $ nf sign bs128
      , bench "1 MB"  $ nf sign mb1
      , bench "5 MB"  $ nf sign mb5
      ]
    , bgroup "sign+verify"
      [ bench "128 B" $ nf verify bs128
      , bench "1 MB"  $ nf verify mb1
      , bench "5 MB"  $ nf verify mb5
      ]
    , bgroup "signDetached"
      [ bench "128 B" $ nf signDetached bs128
      , bench "1 MB"  $ nf signDetached mb1
      , bench "5 MB"  $ nf signDetached mb5
      ]
    , bgroup "signDetached+verifyDetached"
      [ bench "128 B" $ nf signVerifyDetached bs128
      , bench "1 MB"  $ nf signVerifyDetached mb1
      , bench "5 MB"  $ nf signVerifyDetached mb5
      ]
    ]

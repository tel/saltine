module AuthBench (benchAuth, authEnv) where

import Criterion.Main

import Control.Monad
import Control.DeepSeq
import Control.Exception
import Data.ByteString as BS

import Crypto.Saltine.Core.Auth

import BenchUtils


authEnv :: IO Key
authEnv = newKey

benchAuth :: Key -> Benchmark
benchAuth k = do
  let authVerify :: ByteString -> Bool
      authVerify message = do
        let authenticator = auth k message
        verify k authenticator message

  bgroup "Auth"
    [ bench "newKey" $ nfIO newKey
    , bgroup "auth"
      [ bench "128 B" $ nf (auth k) bs128
      , bench "1 MB"  $ nf (auth k) mb1
      , bench "5 MB"  $ nf (auth k) mb5
      ]
    , bgroup "auth+verify"
      [ bench "128 B" $ nf authVerify bs128
      , bench "1 MB"  $ nf authVerify mb1
      , bench "5 MB"  $ nf authVerify mb5
      ]
    ]

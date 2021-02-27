module ConstantTimeBench (benchComparison) where

import Criterion.Main

import Control.Monad
import Control.DeepSeq
import Control.Exception
import Data.ByteString              as BS

import Crypto.Saltine.Core.Auth     as A
import Crypto.Saltine.Class
import Crypto.Saltine.Internal.Util as U

import BenchUtils

benchComparison :: Benchmark
benchComparison =
  bgroup "ConstantTime"
    [ bench "Compare two \"keys\" using ByteString comparison" $ nfIO $ do
        k1 <- randomByteString (2^20)
        k2 <- randomByteString (2^20)

        pure $ k1 == k2
    , bench "Compare two keys using constant-time comparison" $ nfIO $ do
        k1 <- randomByteString (2^20)
        k2 <- randomByteString (2^20)

        pure $ U.compare k1 k2
    ]

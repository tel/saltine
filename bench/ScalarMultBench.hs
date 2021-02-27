module ScalarMultBench (benchScalarMult, scalarMultEnv) where

import Criterion.Main

import Control.Monad
import Control.DeepSeq
import Control.Exception
import Data.ByteString as BS

import Data.Maybe (fromJust)

import Crypto.Saltine.Class
import Crypto.Saltine.Core.ScalarMult as S
import Crypto.Saltine.Internal.ScalarMult as Bytes
import Crypto.Saltine.Internal.Util

import BenchUtils

scalarMultEnv :: IO (GroupElement, Scalar)
scalarMultEnv = do
    bsge <- randomByteString Bytes.mult
    bssc <- randomByteString Bytes.multScalar

    let ge = fromJust $ decode bsge
    let sc = fromJust $ decode bssc

    pure (ge,sc)


benchScalarMult :: (GroupElement, Scalar) -> Benchmark
benchScalarMult (ge,sc) =
  bgroup "ScalarMult"
    [ bench "mult"     $ nf (S.mult    sc) ge
    , bench "multBase" $ nf S.multBase sc
    ]

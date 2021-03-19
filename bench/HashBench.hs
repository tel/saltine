module HashBench (benchHash, hashEnv) where

import Criterion

import Control.Monad

import Crypto.Saltine.Core.Hash
import Crypto.Saltine.Core.Utils

import BenchUtils
import Data.Maybe (fromJust)

hashEnv :: IO (ShorthashKey, GenerichashKey, GenerichashOutLen)
hashEnv = do
    shk <- newShorthashKey
    ghk <- fromJust <$> newGenerichashKey 48
    let ghol = fromJust (generichashOutLen 48)

    pure (shk,ghk,ghol)

benchHash :: (ShorthashKey, GenerichashKey, GenerichashOutLen) -> Benchmark
benchHash (shk,ghk,ghol) =
  bgroup "Hash"
    [ bgroup "hash"
      [ bench "128 B" $ nf hash bs128
      , bench "1 MB"  $ nf hash mb1
      , bench "5 MB"  $ nf hash mb5
      ]
    , bgroup "shortHash"
      [ bench "128 B" $ nf (shorthash shk) bs128
      , bench "2 KB"  $ nf (shorthash shk) kb2
      , bench "1 MB"  $ nf (shorthash shk) mb1
      ]
    , bgroup "genericHash"
      [ bench "128 B" $ nf (generichash ghk bs128) ghol
      , bench "2 KB"  $ nf (generichash ghk kb2  ) ghol
      , bench "1 MB"  $ nf (generichash ghk mb1  ) ghol
      , bench "5 MB"  $ nf (generichash ghk mb5  ) ghol
      ]
    ]

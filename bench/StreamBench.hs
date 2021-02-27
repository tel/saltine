module StreamBench (benchStream, streamEnv) where

import Criterion.Main

import Control.Monad
import Control.DeepSeq
import Control.Exception
import Data.ByteString as BS

import Crypto.Saltine.Core.Stream as S

import BenchUtils

streamEnv :: IO Key
streamEnv = newKey

benchStream :: Key -> Benchmark
benchStream k = do
  let stream :: Int -> IO ByteString
      stream i = newNonce >>= \n -> pure $ S.stream k n i

      xor :: ByteString -> IO ByteString
      xor m = newNonce >>= \n -> pure $ S.xor k n m

  bgroup "Stream"
    [ bench "newKey" $ nfIO newKey
    , bgroup "stream"
      [ bench "128 B" $ nfIO $ stream (2^7)
      , bench "1 MB"  $ nfIO $ stream (2^20)
      , bench "16 MB" $ nfIO $ stream (2^24)
      ]
    , bgroup "xor"
      [ bench "128 B" $ nfIO $ xor bs128
      , bench "1 MB"  $ nfIO $ xor mb1
      , bench "5 MB"  $ nfIO $ xor mb5
      ]
    ]

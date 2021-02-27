module RandomBench (benchRandom) where

import Criterion

import Data.ByteString (ByteString)
import Crypto.Saltine.Core.Utils

benchRandom = bgroup "random"
  [ bench "32 B"   $ nfIO (randomByteString 32          :: IO ByteString)
  , bench "128 B"  $ nfIO (randomByteString 128         :: IO ByteString)
  , bench "512 B"  $ nfIO (randomByteString 512         :: IO ByteString)
  , bench "2 KB"   $ nfIO (randomByteString 2000        :: IO ByteString)
  , bench "8 KB"   $ nfIO (randomByteString 8000        :: IO ByteString)
  , bench "32 KB"  $ nfIO (randomByteString 32000       :: IO ByteString)
  , bench "128 KB" $ nfIO (randomByteString 128000      :: IO ByteString)
  , bench "512 KB" $ nfIO (randomByteString 512000      :: IO ByteString)
  , bench "2 MB"   $ nfIO (randomByteString 2000000     :: IO ByteString)
  , bench "8 MB"   $ nfIO (randomByteString 8000000     :: IO ByteString)
  , bench "32 MB"  $ nfIO (randomByteString 32000000    :: IO ByteString)
  , bench "128 MB" $ nfIO (randomByteString 128000000   :: IO ByteString)
  ]

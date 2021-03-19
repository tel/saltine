module PasswordBench (benchPassword, passwordEnv) where

import Criterion.Main

import Control.Monad
import Control.DeepSeq
import Control.Exception
import Data.ByteString as BS

import Crypto.Saltine.Core.Password as P

import BenchUtils

passwordEnv :: IO Salt
passwordEnv = newSalt

benchPassword :: Salt -> Benchmark
benchPassword s = do
  let hashAndVerify :: ByteString -> IO Bool
      hashAndVerify p = pure $ pwhashStrVerify (pwhashStr p interactivePolicy) p

      hashAndRehash :: ByteString -> IO (Maybe Bool)
      hashAndRehash p = pure $ needsRehash interactivePolicy (pwhashStr p interactivePolicy)

  bgroup "Password"
    [ bench "newSalt" $ nfIO newSalt
    , bgroup "hash + verify"
      [ bench "128 B" $ nfIO $ hashAndVerify bs128
      , bench "2 KB"  $ nfIO $ hashAndVerify kb2
      ]
    , bgroup "needsRehash"
      [ bench "128 B" $ nfIO $ hashAndRehash bs128
      , bench "2 KB"  $ nfIO $ hashAndRehash kb2
      ]
    , bgroup "pwhash"
      [ bench "128 B + 256"  $ nf (pwhash bs128 (2^8 ) s) interactivePolicy
      , bench "128 B + 512"  $ nf (pwhash bs128 (2^9 ) s) interactivePolicy
      , bench "128 B + 1024" $ nf (pwhash bs128 (2^10) s) interactivePolicy
      , bench "128 B + 2048" $ nf (pwhash bs128 (2^11) s) interactivePolicy
      , bench "128 B + 4096" $ nf (pwhash bs128 (2^12) s) interactivePolicy
      , bench "128 B + 8192" $ nf (pwhash bs128 (2^13) s) interactivePolicy
      ]
    ]

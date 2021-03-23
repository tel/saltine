module PasswordBench (benchPassword, passwordEnv) where

import Criterion.Main

import Control.Monad
import Control.DeepSeq
import Control.Exception
import Data.ByteString as BS
import Data.Maybe      (fromJust)
import Data.Text       (Text)

import Crypto.Saltine.Core.Password as P

import BenchUtils

passwordEnv :: IO Salt
passwordEnv = newSalt

benchPassword :: Salt -> Benchmark
benchPassword s = do
  let hashAndVerify :: Text -> Policy ->  IO Bool
      hashAndVerify p pol = do
          h <- pwhashStr p pol
          pure $ pwhashStrVerify (fromJust h) p

      hashAndRehash :: Text -> Policy -> IO (Maybe Bool)
      hashAndRehash p pol = do
          h <- pwhashStr p pol
          pure $ needsRehash (opsPolicy pol) (memPolicy pol) (fromJust h)

  bgroup "Password"
    [ bench "newSalt" $ nfIO newSalt
    , bgroup "hash + verify"
      [ bgroup "interactive"
        [ bench "128 B" $ nfIO $ hashAndVerify s128  interactivePolicy
        , bench "2 KB"  $ nfIO $ hashAndVerify s2000 interactivePolicy
        ]
      , bgroup "moderate"
        [ bench "128 B" $ nfIO $ hashAndVerify s128  moderatePolicy
        , bench "2 KB"  $ nfIO $ hashAndVerify s2000 moderatePolicy
        ]
      , bgroup "sensitive"
        [ bench "128 B" $ nfIO $ hashAndVerify s128  sensitivePolicy
        , bench "2 KB"  $ nfIO $ hashAndVerify s2000 sensitivePolicy
        ]
      ]
    , bgroup "needsRehash"
      [ bgroup "interactive"
        [ bench "128 B" $ nfIO $ hashAndRehash s128  interactivePolicy
        , bench "2 KB"  $ nfIO $ hashAndRehash s2000 interactivePolicy
        ]
      , bgroup "moderate"
        [ bench "128 B" $ nfIO $ hashAndRehash s128  moderatePolicy
        , bench "2 KB"  $ nfIO $ hashAndRehash s2000 moderatePolicy
        ]
      , bgroup "sensitive"
        [ bench "128 B" $ nfIO $ hashAndRehash s128  sensitivePolicy
        , bench "2 KB"  $ nfIO $ hashAndRehash s2000 sensitivePolicy
        ]
      ]
    , bgroup "pwhash"
      [ bgroup "interactive"
        [ bench "128 B + 256"  $ nf (pwhash s128 (2^8 ) s) interactivePolicy
        , bench "128 B + 512"  $ nf (pwhash s128 (2^9 ) s) interactivePolicy
        , bench "128 B + 1024" $ nf (pwhash s128 (2^10) s) interactivePolicy
        , bench "128 B + 2048" $ nf (pwhash s128 (2^11) s) interactivePolicy
        , bench "128 B + 4096" $ nf (pwhash s128 (2^12) s) interactivePolicy
        , bench "128 B + 8192" $ nf (pwhash s128 (2^13) s) interactivePolicy
        ]
      , bgroup "moderate"
        [ bench "128 B + 256"  $ nf (pwhash s128 (2^8 ) s) moderatePolicy
        , bench "128 B + 512"  $ nf (pwhash s128 (2^9 ) s) moderatePolicy
        , bench "128 B + 1024" $ nf (pwhash s128 (2^10) s) moderatePolicy
        , bench "128 B + 2048" $ nf (pwhash s128 (2^11) s) moderatePolicy
        , bench "128 B + 4096" $ nf (pwhash s128 (2^12) s) moderatePolicy
        , bench "128 B + 8192" $ nf (pwhash s128 (2^13) s) moderatePolicy
        ]
      , bgroup "sensitive"
        [ bench "128 B + 256"  $ nf (pwhash s128 (2^8 ) s) sensitivePolicy
        , bench "128 B + 512"  $ nf (pwhash s128 (2^9 ) s) sensitivePolicy
        , bench "128 B + 1024" $ nf (pwhash s128 (2^10) s) sensitivePolicy
        , bench "128 B + 2048" $ nf (pwhash s128 (2^11) s) sensitivePolicy
        , bench "128 B + 4096" $ nf (pwhash s128 (2^12) s) sensitivePolicy
        , bench "128 B + 8192" $ nf (pwhash s128 (2^13) s) sensitivePolicy
        ]
      ]
    ]

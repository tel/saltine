module SecretBoxBench (benchSecretbox, secretboxEnv) where

import Criterion.Main

import Control.Monad
import Control.DeepSeq
import Control.Exception
import Data.ByteString as BS

import Crypto.Saltine.Core.SecretBox

import BenchUtils


secretboxEnv :: IO Key
secretboxEnv = newKey

benchSecretbox :: Key -> Benchmark
benchSecretbox k = do
  let encrypt :: ByteString -> IO ByteString
      encrypt msg = newNonce >>= \n -> pure $ secretbox k n msg

      decrypt :: ByteString -> IO (Maybe ByteString)
      decrypt msg = do
        n <- newNonce
        let ciphertext = secretbox k n msg
        return $ secretboxOpen k n ciphertext

      encryptDetached msg = newNonce >>= \n -> pure $ secretboxDetached k n msg
      decryptDetached msg = do
          n <- newNonce
          let (t,c) = secretboxDetached k n msg
          pure $ secretboxOpenDetached k n t c

  bgroup "Box"
    [ bench "newKey" $ nfIO newKey
    , bgroup "encrypt"
      [ bench "128 B" $ nfIO $ encrypt bs128
      , bench "1 MB"  $ nfIO $ encrypt mb1
      , bench "5 MB"  $ nfIO $ encrypt mb5
      ]
    , bgroup "encrypt+decrypt"
      [ bench "128 B" $ nfIO $ decrypt bs128
      , bench "1 MB"  $ nfIO $ decrypt mb1
      , bench "5 MB"  $ nfIO $ decrypt mb5
      ]
    , bgroup "encryptDetached"
      [ bench "128 B" $ nfIO $ encryptDetached bs128
      , bench "1 MB"  $ nfIO $ encryptDetached mb1
      , bench "5 MB"  $ nfIO $ encryptDetached mb5
      ]
    , bgroup "encryptDetached+decryptDetached"
      [ bench "128 B" $ nfIO $ decryptDetached bs128
      , bench "1 MB"  $ nfIO $ decryptDetached mb1
      , bench "5 MB"  $ nfIO $ decryptDetached mb5
      ]
    ]

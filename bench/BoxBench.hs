module BoxBench (benchBox, boxEnv) where

import Criterion.Main

import Control.Monad
import Control.DeepSeq
import Control.Exception
import Data.ByteString as BS

import Crypto.Saltine.Core.Box

import BenchUtils


boxEnv :: IO (Keypair, Keypair)
boxEnv = do
  alice <- newKeypair
  bob   <- newKeypair
  return (alice, bob)


benchBox :: (Keypair, Keypair) -> Benchmark
benchBox (alice, bob) = do
  let encrypt :: ByteString -> IO ByteString
      encrypt b = newNonce >>= \n -> pure $ box (snd bob) (fst alice) n b

      decrypt :: ByteString -> IO (Maybe ByteString)
      decrypt message = do
        n <- newNonce
        let ciphertext = box (snd alice) (fst bob) n message
        return $ boxOpen (snd bob) (fst alice) n ciphertext

  bgroup "Box"
    [ bench "newKeypair" $ nfIO newKeypair
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
    ]

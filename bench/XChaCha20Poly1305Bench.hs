module XChaCha20Poly1305Bench (benchXChaCha20Poly1305, xChaCha20Poly1305Env) where

import Criterion.Main

import Control.Monad
import Control.DeepSeq
import Control.Exception
import Data.ByteString as BS

import Crypto.Saltine.Core.AEAD.XChaCha20Poly1305 as C

import BenchUtils

xChaCha20Poly1305Env :: IO Key
xChaCha20Poly1305Env = newKey

benchXChaCha20Poly1305 :: Key -> Benchmark
benchXChaCha20Poly1305 k = do
  let encrypt :: ByteString -> ByteString -> IO ByteString
      encrypt msg aad = newNonce >>= \n -> pure $ C.aead k n msg aad

      decrypt :: ByteString -> ByteString -> IO (Maybe ByteString)
      decrypt msg aad = do
        n <- newNonce
        let ciphertext = C.aead k n msg aad
        return $ C.aeadOpen k n ciphertext aad

      encryptDetached msg aad = newNonce >>= \n -> pure $ C.aeadDetached k n msg aad
      decryptDetached msg aad = do
        n <- newNonce
        let (t,c) = C.aeadDetached k n msg aad
        pure $ C.aeadOpenDetached k n t c aad

  bgroup "XChaCha20Poly1305"
    [ bench "newKey" $ nfIO newKey
    , bgroup "aead"
      [ bench "128 B + 128 B" $ nfIO $ encrypt bs128 bs128
      , bench "128 B + 5 MB"  $ nfIO $ encrypt bs128 mb5
      , bench "1 MB + 128 B"  $ nfIO $ encrypt mb1   bs128
      , bench "1 MB + 5 B"    $ nfIO $ encrypt mb1   mb5
      , bench "5 MB + 128 B"  $ nfIO $ encrypt mb5   bs128
      , bench "5 MB + 5 MB"   $ nfIO $ encrypt mb5   mb5
      ]
    , bgroup "aead + open"
      [ bench "128 B + 128 B" $ nfIO $ decrypt bs128 bs128
      , bench "128 B + 5 MB"  $ nfIO $ decrypt bs128 mb5
      , bench "1 MB + 128 B"  $ nfIO $ decrypt mb1   bs128
      , bench "1 MB + 5 B"    $ nfIO $ decrypt mb1   mb5
      , bench "5 MB + 128 B"  $ nfIO $ decrypt mb5   bs128
      , bench "5 MB + 5 MB"   $ nfIO $ decrypt mb5   mb5
      ]
    , bgroup "aeadDetached"
      [ bench "128 B + 128 B" $ nfIO $ encryptDetached bs128 bs128
      , bench "128 B + 5 MB"  $ nfIO $ encryptDetached bs128 mb5
      , bench "1 MB + 128 B"  $ nfIO $ encryptDetached mb1   bs128
      , bench "1 MB + 5 B"    $ nfIO $ encryptDetached mb1   mb5
      , bench "5 MB + 128 B"  $ nfIO $ encryptDetached mb5   bs128
      , bench "5 MB + 5 MB"   $ nfIO $ encryptDetached mb5   mb5
      ]
    , bgroup "aeadDetached + openDetached"
      [ bench "128 B + 128 B" $ nfIO $ decryptDetached bs128 bs128
      , bench "128 B + 5 MB"  $ nfIO $ decryptDetached bs128 mb5
      , bench "1 MB + 128 B"  $ nfIO $ decryptDetached mb1   bs128
      , bench "1 MB + 5 B"    $ nfIO $ decryptDetached mb1   mb5
      , bench "5 MB + 128 B"  $ nfIO $ decryptDetached mb5   bs128
      , bench "5 MB + 5 MB"   $ nfIO $ decryptDetached mb5   mb5
      ]
    ]

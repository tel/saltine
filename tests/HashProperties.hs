{-# LANGUAGE OverloadedStrings #-}

module HashProperties (
  testHash
  ) where

import           Util
import           Crypto.Saltine.Core.Hash

import qualified Data.ByteString                      as S
import           Test.Framework.Providers.QuickCheck2
import           Test.Framework
import           Test.QuickCheck

testHash :: Test
testHash = buildTest $ do
  shKey <- newShorthashKey
  shKey2 <- newShorthashKey
  ghKey <- newGenerichashKey 24 >>= maybe undefined return
  ghKey2 <- newGenerichashKey 24 >>= maybe undefined return
  let ghOutLen = maybe undefined id $ generichashOutLen 32

  return $ testGroup "...Internal.Hash" [

    testProperty "No two hashes are alike"
    $ \(Message bs1, Message bs2) -> bs1 /= bs2 ==> hash bs1 /= hash bs2,

    testProperty "Hash of empty ByteString is correct"
    $ \(Message bs) -> (bs == S.empty) ==> hash bs == (read hashEmptyBS :: S.ByteString),

    testProperty "SHA256 of empty ByteString is correct"
    $ \(Message bs) -> (bs == S.empty) ==> sha256 bs == (read sha256EmptyBS :: S.ByteString),

    testProperty "No two shorthashes are alike"
    $ \(Message bs1, Message bs2) -> bs1 /= bs2 ==> shorthash shKey bs1 /= shorthash shKey bs2,

    testProperty "Different keys produce different shorthashes"
    $ \(Message bs) -> shorthash shKey bs /= shorthash shKey2 bs,

    testProperty "No two generic hashes are alike"
    $ \(Message bs1, Message bs2) -> bs1 /= bs2 ==> generichash ghKey bs1 ghOutLen /= generichash ghKey bs2 ghOutLen,

    testProperty "No two SHA256 hashes are alike"
    $ \(Message bs1, Message bs2) -> bs1 /= bs2 ==> sha256 bs1 /= sha256 bs2,

    testProperty "Different keys produce different generichashes"
    $ \(Message bs) -> generichash ghKey bs ghOutLen /= generichash ghKey2 bs ghOutLen

    ]

  where
    hashEmptyBS   = "\"\207\131\225\&5~\239\184\189\241T(P\214m\128\a\214 \228\ENQ\vW\NAK\220\131\244\169!\211l\233\206G\208\209<]\133\242\176\255\131\CAN\210\135~\236/c\185\&1\189GAz\129\165\&82z\249'\218>\""
    sha256EmptyBS = "\"\227\176\196B\152\252\FS\DC4\154\251\244\200\153o\185$'\174A\228d\155\147L\164\149\153\ESCxR\184U\""

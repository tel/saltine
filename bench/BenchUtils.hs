module BenchUtils where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Data.Text as T

bs128, kb2, mb1, mb5 :: ByteString
bs128 = BS.replicate 128     0
kb2   = BS.replicate 2000    0
mb1   = BS.replicate 1000000 0
mb5   = BS.replicate 5000000 0

s128  = T.replicate 128  (T.pack "0")
s2000 = T.replicate 2000 (T.pack "0")

{-# LANGUAGE OverloadedStrings #-}

module Main where

import SecretBoxProperties   (testSecretBox)
import BoxProperties         (testBox)
import SealedBoxProperties   (testSealedBox)
import StreamProperties      (testStream)
import AuthProperties        (testAuth)
import OneTimeAuthProperties (testOneTimeAuth)
import SignProperties        (testSign)
import ScalarMultProperties  (testScalarMult)

import Test.Framework

main :: IO ()
main = defaultMain [
  testBox,
  testSealedBox,
  testSecretBox,
  testStream,
  testAuth,
  testOneTimeAuth,
  testSign,
  testScalarMult
  ]

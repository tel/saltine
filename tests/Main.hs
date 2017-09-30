{-# LANGUAGE OverloadedStrings #-}

module Main where

import SecretBoxProperties   (testSecretBox)
import AEADProperties        (testAEAD)
import BoxProperties         (testBox)
import SealedBoxProperties   (testSealedBox)
import StreamProperties      (testStream)
import AuthProperties        (testAuth)
import OneTimeAuthProperties (testOneTimeAuth)
import SignProperties        (testSign)
import ScalarMultProperties  (testScalarMult)

import Test.Framework

main :: IO ()
main = flip defaultMainWithOpts mempty { ropt_color_mode = Just ColorAlways } [
  testBox,
  testSealedBox,
  testSecretBox,
  testAEAD,
  testStream,
  testAuth,
  testOneTimeAuth,
  testSign,
  testScalarMult
  ]

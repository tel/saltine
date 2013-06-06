{-# LANGUAGE OverloadedStrings #-}

module Main where

import SecretBoxProperties (testSecretBox)
import BoxProperties (testBox)
import StreamProperties (testStream)
import AuthProperties (testAuth)
import OneTimeAuthProperties (testOneTimeAuth)
import SignProperties (testSign)

import Test.Framework

main :: IO ()
main = defaultMain [
  testBox,
  testSecretBox,
  testStream,
  testAuth,
  testOneTimeAuth,
  testSign
  ]
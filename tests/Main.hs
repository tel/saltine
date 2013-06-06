{-# LANGUAGE OverloadedStrings #-}

module Main where

import SecretBoxProperties (testSecretBox)
import BoxProperties (testBox)

import Test.Framework

-- Need to use Test.Framework in order to make this work with Cabal.

main :: IO ()
main = defaultMain [
  testBox,
  testSecretBox
  ]
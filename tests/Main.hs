{-# LANGUAGE OverloadedStrings #-}

module Main where

import SecretBoxProperties (testSecretBox)
import BoxProperties (testBox)

import Test.Framework

main :: IO ()
main = defaultMain [
  testBox,
  testSecretBox
  ]
{-# LANGUAGE OverloadedStrings #-}

module Main where

import SecretBoxProperties (testSecretBox)
import BoxProperties (testBox)

-- Need to use Test.Framework in order to make this work with Cabal.

main :: IO ()
main = do
  -- Use a few different key/nonce pairs
  testSecretBox >> testSecretBox >> testSecretBox
  testBox >> testBox >> testBox
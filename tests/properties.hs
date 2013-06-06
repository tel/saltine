{-# LANGUAGE OverloadedStrings #-}

module Main where

import SecretBoxProperties (testSecretBox)
import BoxProperties (testBox)

main :: IO ()
main = do
  -- Use a few different key/nonce pairs
  testSecretBox >> testSecretBox >> testSecretBox
  testBox >> testBox >> testBox
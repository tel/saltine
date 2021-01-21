{-# LANGUAGE OverloadedStrings #-}

module Main where

import SecretBoxProperties   (testSecretBox)
import AEAD.ChaCha20Poly1305Properties      (testAEADChaCha20)
import AEAD.ChaCha20Poly1305IETFProperties  (testAEADIETF)
import AEAD.XChaCha20Poly1305Properties     (testAEADXChaCha20)
import AEAD.AES256GCMProperties             (testAEADAES)
import BoxProperties         (testBox)
import SealedBoxProperties   (testSealedBox)
import StreamProperties      (testStream)
import AuthProperties        (testAuth)
import OneTimeAuthProperties (testOneTimeAuth)
import SignProperties        (testSign)
import HashProperties        (testHash)
import ScalarMultProperties  (testScalarMult)
import UtilProperties        (testUtils)
import Crypto.Saltine

import Data.Monoid
import Test.Framework

runOpts :: RunnerOptions
runOpts = mempty { ropt_color_mode   = Just ColorAlways
                 , ropt_test_options = Just testOpts
                 }

testOpts :: TestOptions
testOpts = mempty { topt_maximum_generated_tests = Just 20000 }

main :: IO ()
main = do
  sodiumInit
  flip defaultMainWithOpts runOpts [
        testUtils,
        testBox,
        testSealedBox,
        testSecretBox,
        testAEADChaCha20,
        testAEADIETF,
        testAEADXChaCha20,
        testAEADAES,
        testStream,
        testAuth,
        testOneTimeAuth,
        testSign,
        testHash,
        testScalarMult
        ]

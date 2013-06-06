{-# LANGUAGE OverloadedStrings #-}

module SecretBoxProperties (
  testSecretBox
  ) where

import Util

import Crypto.Saltine.Core.SecretBox

import qualified Data.Vector.Storable as V

import Control.Applicative

import Test.Framework.Providers.QuickCheck2
import Test.Framework

-- | Ciphertext can be decrypted
rightInverseProp :: Key -> Nonce -> Message -> Bool
rightInverseProp k n (Message bs) =
  Just bs == (toBS <$> secretboxOpen k n (secretbox k n (fromBS bs)))

-- | Ciphertext cannot be decrypted if the ciphertext is perturbed
rightInverseFailureProp :: Key -> Nonce -> Message -> Bool
rightInverseFailureProp k n (Message bs) =
  Nothing == (toBS <$> secretboxOpen k n (V.reverse $ secretbox k n (fromBS bs)))

-- | Ciphertext cannot be decrypted with a different key
cannotDecryptKeyProp :: Key -> Key -> Nonce -> Message -> Bool
cannotDecryptKeyProp k1 k2 n (Message bs) =
  Nothing == (toBS <$> secretboxOpen k2 n (secretbox k1 n (fromBS bs)))

-- | Ciphertext cannot be decrypted with a different nonce
cannotDecryptNonceProp :: Key -> Nonce -> Nonce -> Message -> Bool
cannotDecryptNonceProp k n1 n2 (Message bs) =
  Nothing == (toBS <$> secretboxOpen k n2 (secretbox k n1 (fromBS bs)))

testSecretBox :: Test
testSecretBox = buildTest $ do
  k1 <- newKey
  k2 <- newKey
  n1 <- newNonce
  n2 <- newNonce

  return $ testGroup "...Internal.SecretBox" [

    testProperty "Can decrypt ciphertext"
    $ rightInverseProp k1 n1,

    testGroup "Cannot decrypt ciphertext when..." [

      testProperty "... ciphertext is perturbed"
      $ rightInverseFailureProp k1 n1,

      testProperty "... using the wrong key"
      $ cannotDecryptKeyProp   k1 k2 n1,

      testProperty "... using the wrong nonce"
      $ cannotDecryptNonceProp k1 n1 n2
      
      ]
    ]
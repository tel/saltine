{-# LANGUAGE OverloadedStrings #-}

module SecretBoxProperties (
  testSecretBox
  ) where

import           Util
import           Crypto.Saltine.Core.SecretBox

import qualified Data.ByteString                      as S
import           Test.Framework.Providers.QuickCheck2
import           Test.Framework

-- | Ciphertext can be decrypted
rightInverseProp :: Key -> Nonce -> Message -> Bool
rightInverseProp k n (Message bs) =
  Just bs == secretboxOpen k n (secretbox k n bs)

-- | Detached ciphertext/tag can be decrypted
rightInverseDetachedProp :: Key -> Nonce -> Message -> Bool
rightInverseDetachedProp k n (Message bs) =
  Just bs == uncurry (secretboxOpenDetached k n) (secretboxDetached k n bs)

-- | Ciphertext cannot be decrypted if the ciphertext is perturbed
rightInverseFailureProp :: Key -> Nonce -> Message -> Bool
rightInverseFailureProp k n (Message bs) =
  Nothing == secretboxOpen k n (S.reverse $ secretbox k n bs)

-- | Ciphertext cannot be decrypted if the tag is perturbed
rightInverseTagFailureProp :: Key -> Nonce -> Message -> Bool
rightInverseTagFailureProp k n (Message bs) =
  Nothing == uncurry (secretboxOpenDetached k n) ((\(a,b) -> (a,S.reverse b)) $ secretboxDetached k n bs)

-- | Ciphertext cannot be decrypted if the ciphertext is perturbed
rightInverseFailureDetachedProp :: Key -> Nonce -> Message -> Bool
rightInverseFailureDetachedProp k n (Message bs) =
  Nothing == uncurry (secretboxOpenDetached k n) ((\(a,b) -> (S.reverse a, b)) $ secretboxDetached k n bs)
  || S.length bs == 0

-- | Ciphertext cannot be decrypted with a different key
cannotDecryptKeyProp :: Key -> Key -> Nonce -> Message -> Bool
cannotDecryptKeyProp k1 k2 n (Message bs) =
  Nothing == secretboxOpen k2 n (secretbox k1 n bs)

-- | Ciphertext cannot be decrypted with a different key
cannotDecryptKeyDetachedProp :: Key -> Key -> Nonce -> Message -> Bool
cannotDecryptKeyDetachedProp k1 k2 n (Message bs) =
  Nothing == uncurry (secretboxOpenDetached k2 n) (secretboxDetached k1 n bs)

-- | Ciphertext cannot be decrypted with a different nonce
cannotDecryptNonceProp :: Key -> Nonce -> Nonce -> Message -> Bool
cannotDecryptNonceProp k n1 n2 (Message bs) =
  Nothing == secretboxOpen k n2 (secretbox k n1 bs)

-- | Ciphertext cannot be decrypted with a different nonce
cannotDecryptNonceDetachedProp :: Key -> Nonce -> Nonce -> Message -> Bool
cannotDecryptNonceDetachedProp k n1 n2 (Message bs) =
  Nothing == uncurry (secretboxOpenDetached k n2) (secretboxDetached k n1 bs)

testSecretBox :: Test
testSecretBox = buildTest $ do
  k1 <- newKey
  k2 <- newKey
  n1 <- newNonce
  n2 <- newNonce

  return $ testGroup "...Internal.SecretBox" [

    testProperty "Can decrypt ciphertext"
    $ rightInverseProp k1 n1,

    testProperty "Can decrypt ciphertext (detached)"
    $ rightInverseDetachedProp k1 n1,

    testGroup "Cannot decrypt ciphertext when..." [

      testProperty "... ciphertext is perturbed"
      $ rightInverseFailureProp k1 n1,

      testProperty "... ciphertext is perturbed (detached)"
      $ rightInverseFailureDetachedProp k1 n1,

      testProperty "... tag is perturbed (detached)"
      $ rightInverseTagFailureProp k1 n1,

      testProperty "... using the wrong key"
      $ cannotDecryptKeyProp   k1 k2 n1,

      testProperty "... using the wrong key (detached)"
      $ cannotDecryptKeyDetachedProp   k1 k2 n1,

      testProperty "... using the wrong nonce"
      $ cannotDecryptNonceProp k1 n1 n2,

      testProperty "... using the wrong nonce (detached"
      $ cannotDecryptNonceDetachedProp k1 n1 n2

      ]
    ]

{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module SecretBoxProperties (
  testSecretBox
  ) where

import           Util
import           Crypto.Saltine.Core.SecretBox
import           Crypto.Saltine.Class
import           Crypto.Saltine.Internal.ByteSizes as Bytes

import qualified Data.ByteString                      as S
import           Test.Framework.Providers.QuickCheck2
import           Test.Framework
import           Test.QuickCheck (Property, (==>))
import           Test.QuickCheck.Arbitrary

instance Arbitrary Nonce where
    arbitrary =
        do bs <- S.pack <$> vector Bytes.secretBoxNonce
           maybe (fail "impossible arbitrary failure.") pure (decode bs)

instance Arbitrary Key where
    arbitrary =
        do bs <- S.pack <$> vector Bytes.secretBoxKey
           maybe (fail "impossible arbitrary failure.") pure (decode bs)
instance Show Key where
    show = show . encode
instance Show Nonce where
    show = show . encode

-- | Ciphertext can be decrypted
rightInverseProp :: Key -> Nonce -> Message -> Bool
rightInverseProp k n (Message bs) =
  Just bs == secretboxOpen k n (secretbox k n bs)

-- | Detached ciphertext/tag can be decrypted
rightInverseDetachedProp :: Key -> Nonce -> Message -> Bool
rightInverseDetachedProp k n (Message bs) =
  Just bs == uncurry (secretboxOpenDetached k n) (secretboxDetached k n bs)

-- | Ciphertext cannot be decrypted if the ciphertext is perturbed
rightInverseFailureProp :: Key -> Nonce -> Message -> Perturb -> Property
rightInverseFailureProp k n (Message bs) p =
  S.length bs /= 0 ==> Nothing == secretboxOpen k n (perturb (secretbox k n bs) p)

-- | Ciphertext cannot be decrypted if the tag is perturbed
rightInverseTagFailureProp :: Key -> Nonce -> Message -> Message -> Bool
rightInverseTagFailureProp k n (Message bs) (Message fakeTag) =
  Nothing == uncurry (secretboxOpenDetached k n) ((\(a,_) -> (a,fakeTag)) $ secretboxDetached k n bs)

-- | Ciphertext cannot be decrypted if the ciphertext is perturbed
rightInverseFailureDetachedProp :: Key -> Nonce -> Message -> Perturb -> Property
rightInverseFailureDetachedProp k n (Message bs) p =
  S.length bs /= 0 ==> Nothing == uncurry (secretboxOpenDetached k n) ((\(a,b) -> (perturb a p, b)) $ secretboxDetached k n bs)
  || S.length bs == 0

-- | Ciphertext cannot be decrypted with a different key
cannotDecryptKeyProp :: Key -> Key -> Nonce -> Message -> Property
cannotDecryptKeyProp k1 k2 n (Message bs) =
  k1 /= k2 ==> Nothing == secretboxOpen k2 n (secretbox k1 n bs)

-- | Ciphertext cannot be decrypted with a different key
cannotDecryptKeyDetachedProp :: Key -> Key -> Nonce -> Message -> Property
cannotDecryptKeyDetachedProp k1 k2 n (Message bs) =
  k1 /= k2 ==> Nothing == uncurry (secretboxOpenDetached k2 n) (secretboxDetached k1 n bs)

-- | Ciphertext cannot be decrypted with a different nonce
cannotDecryptNonceProp :: Key -> Nonce -> Nonce -> Message -> Property
cannotDecryptNonceProp k n1 n2 (Message bs) =
  n1 /= n2 ==> Nothing == secretboxOpen k n2 (secretbox k n1 bs)

-- | Ciphertext cannot be decrypted with a different nonce
cannotDecryptNonceDetachedProp :: Key -> Nonce -> Nonce -> Message -> Property
cannotDecryptNonceDetachedProp k n1 n2 (Message bs) =
  n1 /= n2 ==> Nothing == uncurry (secretboxOpenDetached k n2) (secretboxDetached k n1 bs)

testSecretBox :: Test
testSecretBox = buildTest $ do

  return $ testGroup "...Internal.SecretBox" [

    testProperty "Can decrypt ciphertext"
    $ rightInverseProp,

    testProperty "Can decrypt ciphertext (detached)"
    $ rightInverseDetachedProp,

    testGroup "Cannot decrypt ciphertext when..." [

      testProperty "... ciphertext is perturbed"
      $ rightInverseFailureProp,

      testProperty "... ciphertext is perturbed (detached)"
      $ rightInverseFailureDetachedProp,

      testProperty "... tag is perturbed (detached)"
      $ rightInverseTagFailureProp,

      testProperty "... using the wrong key"
      $ cannotDecryptKeyProp,

      testProperty "... using the wrong key (detached)"
      $ cannotDecryptKeyDetachedProp,

      testProperty "... using the wrong nonce"
      $ cannotDecryptNonceProp,

      testProperty "... using the wrong nonce (detached"
      $ cannotDecryptNonceDetachedProp

      ]
    ]

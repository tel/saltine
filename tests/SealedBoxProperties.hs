{-# LANGUAGE OverloadedStrings #-}

module SealedBoxProperties (
  testSealedBox
) where

import           Util
import           Crypto.Saltine.Core.Box

import qualified Data.ByteString                      as S
import           Test.Framework.Providers.QuickCheck2
import           Test.Framework

-- | Ciphertext can be decrypted
rightInverseProp :: Keypair -> Message -> Bool
rightInverseProp (sk1, pk1) (Message bs) =
  Just bs == boxSealOpen pk1 sk1 (boxSeal pk1 bs)

-- | Cannot decrypt without the correct secret key
rightInverseFailureProp1 :: Keypair -> Message -> Bool
rightInverseFailureProp1 (sk1, pk1) (Message bs) =
  Nothing == boxSealOpen pk1 (perturb sk1) (boxSeal pk1 bs)

-- | Cannot decrypt without the correct public key
rightInverseFailureProp2 :: Keypair -> Message -> Bool
rightInverseFailureProp2 (sk1, pk1) (Message bs) =
  Nothing == boxSealOpen (perturb pk1) sk1 (boxSeal pk1 bs)

-- | Cannot decrypt when not sent to you
rightInverseFailureProp3 :: Keypair -> Message -> Bool
rightInverseFailureProp3 (sk1, pk1) (Message bs) =
  Nothing == boxSealOpen pk1 sk1 (boxSeal (perturb pk1) bs)

-- | Ciphertext cannot be decrypted (verification failure) if the
-- ciphertext is perturbed
rightInverseFailureProp4 :: Keypair -> Message -> Bool
rightInverseFailureProp4 (sk1, pk1) (Message bs) =
  Nothing == boxSealOpen pk1 sk1 (S.reverse $ boxSeal pk1 bs)

testSealedBox :: Test
testSealedBox = buildTest $ do

  (sk1, pk1) <- newKeypair

  return $ testGroup "... SealedBox" [

    testGroup "Can decrypt ciphertext using..." [
       testProperty "... public key/secret key"
       $ rightInverseProp (sk1, pk1)
       ],

    testGroup "Fail to verify ciphertext when..." [
      testProperty "... not using proper secret key"
      $ rightInverseFailureProp1 (sk1, pk1),

      testProperty "... not using proper public key"
      $ rightInverseFailureProp2 (sk1, pk1),

      testProperty "... not actually sent to you"
      $ rightInverseFailureProp3 (sk1, pk1),

      testProperty "... ciphertext has been perturbed"
      $ rightInverseFailureProp4 (sk1, pk1)
      ]
    ]

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE OverloadedLists #-}

module SealedBoxProperties (
  testSealedBox
) where

import           Util
import           Crypto.Saltine.Core.Box
import           Data.Monoid

import qualified Data.ByteString                      as S
import           Test.Framework.Providers.QuickCheck2
import           Test.Framework
import           Test.QuickCheck.Property               (ioProperty)

-- | Ciphertext can be decrypted
rightInverseProp :: Keypair -> Message -> IO Bool
rightInverseProp (sk1, pk1) (Message bs) = do
  enc <- boxSeal pk1 bs
  return (Just bs == boxSealOpen pk1 sk1 enc)

-- | Cannot decrypt without the correct secret key
rightInverseFailureProp1 :: Keypair -> Message -> Perturb -> IO Bool
rightInverseFailureProp1 (sk1, pk1) (Message bs) p = do
  enc <- boxSeal pk1 bs
  return (Nothing == boxSealOpen pk1 (perturb sk1 ([0] <> p)) enc)

-- | Cannot decrypt without the correct public key
rightInverseFailureProp2 :: Keypair -> Message -> Perturb -> IO Bool
rightInverseFailureProp2 (sk1, pk1) (Message bs) p = do
  enc <- boxSeal pk1 bs
  return (Nothing == boxSealOpen (perturb pk1 p) sk1 enc)

-- | Cannot decrypt when not sent to you
rightInverseFailureProp3 :: Keypair -> Message -> Perturb -> IO Bool
rightInverseFailureProp3 (sk1, pk1) (Message bs) p = do
  enc <- boxSeal (perturb pk1 p) bs
  return (Nothing == boxSealOpen pk1 sk1 enc)

-- | Ciphertext cannot be decrypted (verification failure) if the
-- ciphertext is perturbed
rightInverseFailureProp4 :: Keypair -> Message -> Perturb -> IO Bool
rightInverseFailureProp4 (sk1, pk1) (Message bs) p = do
  enc <- boxSeal pk1 bs
  return (Nothing == boxSealOpen pk1 sk1 (perturb enc p))

testSealedBox :: Test
testSealedBox = buildTest $ do

  (sk1, pk1) <- newKeypair

  return $ testGroup "... SealedBox" [

    testGroup "Can decrypt ciphertext using..." [
       testProperty "... public key/secret key"
       $ ioProperty . rightInverseProp (sk1, pk1)
       ],

    testGroup "Fail to verify ciphertext when..." [
      testProperty "... not using proper secret key"
      $ ioProperty . uncurry (rightInverseFailureProp1 (sk1, pk1)),

      testProperty "... not using proper public key"
      $ ioProperty . uncurry (rightInverseFailureProp2 (sk1, pk1)),

      testProperty "... not actually sent to you"
      $ ioProperty . uncurry (rightInverseFailureProp3 (sk1, pk1)),

      testProperty "... ciphertext has been perturbed"
      $ ioProperty . uncurry ( rightInverseFailureProp4 (sk1, pk1) )
      ]
    ]

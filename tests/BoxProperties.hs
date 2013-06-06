{-# LANGUAGE OverloadedStrings #-}

module BoxProperties (
  testBox
  ) where

import Util

import qualified Crypto.Saltine.Internal.Box as B

import Data.Word
import qualified Data.Vector.Storable as V

import Control.Applicative

import Test.Framework.Providers.QuickCheck2
import Test.Framework

import Test.QuickCheck.Property
import Test.QuickCheck.Monadic

-- | Ciphertext can be decrypted
rightInverseProp
  ::    (V.Vector Word8, V.Vector Word8)
     -> (V.Vector Word8, V.Vector Word8)
     -> V.Vector Word8
     -> Message -> Bool
rightInverseProp (sk1, pk1) (sk2, pk2) n (Message bs) =
  let
    -- person 1 sends encrypting for person 2
    enc = B.box pk2 sk1 n $ fromBS bs
    -- person 2 receives decrypting for person 1
    dec = toBS <$> B.boxOpen pk1 sk2 n enc
  in Just bs == dec

-- | Cannot decrypt without the corrent secret key
rightInverseFailureProp1
  ::    (V.Vector Word8, V.Vector Word8)
     -> (V.Vector Word8, V.Vector Word8)
     -> V.Vector Word8
     -> Message -> Bool
rightInverseFailureProp1 (sk1, pk1) (sk2, pk2) n (Message bs) =
  let
    -- person 1 sends encrypting for person 2
    enc = B.box pk2 sk1 n $ fromBS bs
    -- person 2 receives decrypting for nobody
    dec = toBS <$> B.boxOpen pk1 (V.reverse sk2) n enc
  in Nothing == dec

-- | Cannot decrypt when not sent to you
rightInverseFailureProp2
  ::    (V.Vector Word8, V.Vector Word8)
     -> (V.Vector Word8, V.Vector Word8)
     -> V.Vector Word8
     -> Message -> Bool
rightInverseFailureProp2 (sk1, pk1) (sk2, pk2) n (Message bs) =
  let
    -- person 1 sends encrypting for person 2
    enc = B.box (V.reverse pk2) sk1 n $ fromBS bs
    -- person 2 receives decrypting for nobody
    dec = toBS <$> B.boxOpen pk1 sk2 n enc
  in Nothing == dec

-- | Ciphertext cannot be decrypted (verification failure) if the
-- ciphertext is perturbed
rightInverseFailureProp3
  :: (V.Vector Word8, V.Vector Word8)
     -> (V.Vector Word8, V.Vector Word8)
     -> V.Vector Word8
     -> Message -> Bool
rightInverseFailureProp3 (sk1, pk1) (sk2, pk2) n (Message bs) =
  Nothing == (toBS <$> B.boxOpen pk1 sk2 n (V.reverse $ B.box pk2 sk1 n (fromBS bs)))

-- | Ciphertext cannot be decrypted with a different nonce
cannotDecryptNonceProp
  :: (V.Vector Word8, V.Vector Word8)
     -> (V.Vector Word8, V.Vector Word8)
     -> V.Vector Word8 -> V.Vector Word8
     -> Message -> Bool
cannotDecryptNonceProp (sk1, pk1) (sk2, pk2) n1 n2 (Message bs) =
  Nothing == (toBS <$> B.boxOpen pk1 sk2 n2 (B.box pk2 sk1 n1 (fromBS bs)))

-- | BeforeNM creates identical secret keys when called in an
-- anti-symmetric fashion.
beforeNMCreateSecretKeyProp :: Test.QuickCheck.Property.Property
beforeNMCreateSecretKeyProp = monadicIO . (assert =<<) . run $ do
  (sk1, pk1) <- B.newKeypair
  (sk2, pk2) <- B.newKeypair
  let ck_1for2 = B.beforeNM sk1 pk2
      ck_2for1 = B.beforeNM sk2 pk1
  return (ck_1for2 == ck_2for1)

-- | Ciphertext can be decrypted using combined keys
rightInverseAfterNMProp
  ::    V.Vector Word8 -> V.Vector Word8
     -> V.Vector Word8
     -> Message -> Bool
rightInverseAfterNMProp ck_1for2 ck_2for1 n (Message bs) =
  let
    -- person 1 sends encrypting for person 2
    enc = B.boxAfterNM ck_1for2 n $ fromBS bs
    -- person 2 receives decrypting for person 1
    dec = toBS <$> B.boxOpenAfterNM ck_2for1 n enc
  in Just bs == dec

-- | Perturbed ciphertext cannot be decrypted using combined keys
rightInverseFailureAfterNMProp1
  ::    V.Vector Word8 -> V.Vector Word8
     -> V.Vector Word8
     -> Message -> Bool
rightInverseFailureAfterNMProp1 ck_1for2 ck_2for1 n (Message bs) =
  let
    -- person 1 sends encrypting for person 2
    enc = B.boxAfterNM ck_1for2 n $ fromBS bs
    -- person 2 receives decrypting for person 1
    dec = toBS <$> B.boxOpenAfterNM ck_2for1 n (V.reverse enc)
  in Nothing == dec

testBox :: Test
testBox = buildTest $ do
  (sk1, pk1) <- B.newKeypair
  (sk2, pk2) <- B.newKeypair
  let ck_1for2 = B.beforeNM sk1 pk2
      ck_2for1 = B.beforeNM sk2 pk1
  n1 <- B.newNonce
  n2 <- B.newNonce
  return $ testGroup "...Internal.Box" [

    testGroup "Can decrypt ciphertext using..." [
       
       testProperty "... public key/secret key"
       $ rightInverseProp (sk1, pk1) (sk2, pk2) n1 ,
       
       testProperty "... combined key"
       $ rightInverseAfterNMProp ck_1for2 ck_2for1 n1
       
       ],

    testGroup "Fail to verify ciphertext when..." [
      
      testProperty "... not using proper secret key"
      $ rightInverseFailureProp1 (sk1, pk1) (sk2, pk2) n1,
      
      testProperty "... not actually sent to you"
      $ rightInverseFailureProp2 (sk1, pk1) (sk2, pk2) n1,
      
      testProperty "... ciphertext has been perturbed"
      $ rightInverseFailureProp3 (sk1, pk1) (sk2, pk2) n1,
      
      testProperty "... using the wrong nonce"
      $ cannotDecryptNonceProp (sk1, pk1) (sk2, pk2) n1 n2,
      
      testProperty "... using the wrong combined key"
      $ rightInverseFailureAfterNMProp1 ck_1for2 ck_2for1 n1
      
      ],

    testGroup "(properties)" [

      testProperty "beforeNM is anti-symmetric" beforeNMCreateSecretKeyProp
      
      ]
    ]
    
       

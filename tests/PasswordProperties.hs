{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE OverloadedLists #-}

module PasswordProperties (
  testPassword
) where

import Crypto.Saltine.Core.Password
import Crypto.Saltine.Internal.Util
import Data.Maybe                             (isJust, isNothing, fromJust)
import Data.Text                              (Text)
import Test.Framework.Providers.QuickCheck2
import Test.Framework
import Test.QuickCheck

import qualified Crypto.Saltine.Internal.Password as I
import qualified Data.Text                        as T

instance Arbitrary Text where
    arbitrary = T.pack <$> arbitrary

instance Arbitrary Algorithm where
    arbitrary = elements $ enumFromTo minBound maxBound

-- | Sadly using the actual maximum limit is just way too slow
instance Arbitrary Memlimit where
    arbitrary = I.Memlimit <$> chooseInt ( max I.pwhash_argon2i_memlimit_min I.pwhash_argon2id_memlimit_min
                                         , max I.pwhash_argon2i_memlimit_min I.pwhash_argon2id_memlimit_min * 4
                                         )

instance Arbitrary Opslimit where
    arbitrary = I.Opslimit <$> chooseInt ( max I.pwhash_argon2i_opslimit_min I.pwhash_argon2id_opslimit_min
                                         , max I.pwhash_argon2i_opslimit_min I.pwhash_argon2id_opslimit_min * 4
                                         )

instance Arbitrary Policy where
    arbitrary = applyArbitrary3 Policy

rightInverseProp :: Text -> Policy -> IO Bool
rightInverseProp pw pol = do
    h <- pwhashStr pw pol
    pure $ pwhashStrVerify (fromJust h) pw

rightInverseFailureProp1 :: Text -> Policy -> Text -> IO Bool
rightInverseFailureProp1 pw pol per =
    let npw = T.reverse pw <> T.pack "0" <> per
    in do
        h <- pwhashStr pw pol
        pure . not $ pwhashStrVerify (fromJust h) npw

rightProp :: Text -> Policy -> IO Bool
rightProp pw pol = do
    h <- pwhashStr pw pol
    pure $ Just False == needsRehash (opsPolicy pol) (memPolicy pol) (fromJust h)

rightFailureProp :: Text -> Opslimit -> Opslimit -> Memlimit -> Memlimit -> IO Bool
rightFailureProp pw ops1 ops2 mem1 mem2 = do
    h <- pwhashStr pw (Policy ops1 mem1 defaultAlgorithm)
    pure $ Just True == needsRehash ops2 mem2 (fromJust h)
            || ops1 == ops2

rightFailureProp2 :: Text -> Opslimit -> Memlimit -> Bool
rightFailureProp2 invhash ops mem =
    isNothing $ needsRehash ops mem (I.PasswordHash invhash)

rightProp2 :: Salt -> Text -> Policy -> Gen Bool
rightProp2 salt pw pol = do
    i <- chooseInt (I.pwhash_bytes_min, 1024)

    pure $ isJust $ pwhash pw i salt pol


testPassword :: Test
testPassword = buildTest $ do
  salt <- newSalt

  return $ testGroup "... Password" [

    testProperty "Can hash passwords and verify them..."
        $ ioProperty . uncurry rightInverseProp,

    testProperty "Hashed passwords cannot be verified with the wrong password..."
        $ ioProperty . uncurry3 rightInverseFailureProp1,

    testProperty "Hashed passwords do not need to be rehashed with the same policy..."
        $ ioProperty . uncurry rightProp,

    testProperty "Hashed passwords do need to be rehashed with a different policy..."
        $ ioProperty . uncurry5 rightFailureProp,

    testProperty "needsRehash detects invalid hashes..."
        rightFailureProp2,

    testProperty "Deriving a key from a password..."
        (rightProp2 salt)
    ]

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE OverloadedLists #-}

module PasswordProperties (
  testPassword
) where

import Util
import Crypto.Saltine.Core.Password
import Crypto.Saltine.Internal.Util
import Data.Monoid
import Data.Maybe                             (isJust, isNothing)
import Data.ByteString                        (ByteString)
import Debug.Trace
import Test.Framework.Providers.QuickCheck2
import Test.Framework
import Test.QuickCheck
import Test.QuickCheck.Property               (ioProperty)

import qualified Crypto.Saltine.Internal.Password as I
import qualified Data.ByteString                  as S
import qualified Data.ByteString.Char8            as S8


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

rightInverseProp :: Message -> Policy -> Bool
rightInverseProp (Message pw) pol =
    True == pwhashStrVerify (pwhashStr pw pol) pw

rightInverseFailureProp1 :: Message -> Policy -> Perturb -> Bool
rightInverseFailureProp1 (Message pw) pol per@(Perturb p) =
    let np = perturb pw ([0] <> per)
        np2 = if np == pw then np <> S.pack p else np
    in
        False == pwhashStrVerify (pwhashStr pw pol) np2

rightProp :: Message -> Policy -> Bool
rightProp (Message pw) pol =
    Just False == needsRehash pol (pwhashStr pw pol)

rightFailureProp :: Message -> Policy -> Policy -> Bool
rightFailureProp (Message pw) pol pol2 =
    (Just True == needsRehash pol2 (pwhashStr pw pol))
            || opsPolicy pol == opsPolicy pol2

rightFailureProp2 :: Message -> Policy -> Bool
rightFailureProp2 (Message invhash) pol =
    isNothing $ needsRehash pol (I.PasswordHash invhash)


rightProp2 :: Salt -> Message -> Policy -> Gen Bool
rightProp2 salt (Message bs) pol = do
    i <- chooseInt (I.pwhash_bytes_min, 1024)
    l <- chooseInt (I.pwhash_passwd_min, I.pwhash_passwd_max)

    pure $ isJust $ traceShowId (pwhash bs i salt pol)


testPassword :: Test
testPassword = buildTest $ do
  salt <- newSalt

  return $ testGroup "... Password" [

    testProperty "Can hash passwords and verify them..."
        rightInverseProp,

    testProperty "Hashed passwords cannot be verified with the wrong password..."
        rightInverseFailureProp1,

    testProperty "Hashed passwords do not need to be rehashed with the same policy..."
        rightProp,

    testProperty "Hashed passwords do need to be rehashed with a different policy..."
        rightFailureProp,

    testProperty "needsRehash detects invalid hashes..."
        rightFailureProp2,

    testProperty "Deriving a key from a password..."
        (rightProp2 salt)
    ]

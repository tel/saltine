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

rightInverseProp :: Message -> Policy -> IO Bool
rightInverseProp (Message pw) pol = do
    h <- pwhashStr pw pol
    pure $ pwhashStrVerify h pw

rightInverseFailureProp1 :: Message -> Policy -> Perturb -> IO Bool
rightInverseFailureProp1 (Message pw) pol per@(Perturb p) =
    let np  = perturb pw ([0] <> per)
        np2 = if np == pw then np <> S.pack p else np
    in do
        h <- pwhashStr pw pol
        pure . not $ pwhashStrVerify h np2

rightProp :: Message -> Policy -> IO Bool
rightProp (Message pw) pol = do
    h <- pwhashStr pw pol
    pure $ Just False == needsRehash (opsPolicy pol) (memPolicy pol) h

rightFailureProp :: Message -> Opslimit -> Opslimit -> Memlimit -> Memlimit -> IO Bool
rightFailureProp (Message pw) ops1 ops2 mem1 mem2 = do
    h <- pwhashStr pw (Policy ops1 mem1 defaultAlgorithm)
    pure $ Just True == needsRehash ops2 mem2 h
            || ops1 == ops2

rightFailureProp2 :: Message -> Opslimit -> Memlimit -> Bool
rightFailureProp2 (Message invhash) ops mem =
    isNothing $ needsRehash ops mem (I.PasswordHash invhash)

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

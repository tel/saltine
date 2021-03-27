{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Util where

import           Crypto.Saltine.Class

import           Control.Monad           (replicateM)
import qualified Data.ByteString       as S
import           Data.Word (Word8)
import           Data.Bits (xor)
import           Test.QuickCheck
import           GHC.Exts (IsList(..))

instance IsEncoding S.ByteString where
    encode x = x
    decode x = Just x

perturb :: IsEncoding a => a -> Perturb -> a
perturb a (Perturb p) =
    let bytes = encode a
        len   = S.length bytes
        plen  = length p
        fullP = p <> replicate (len - plen) 0
        newBytes = S.pack $ zipWith xor fullP (S.unpack bytes)
    in case decode newBytes of
        Nothing -> error "Invalid use of perturb on picky encoding."
        Just x  -> x

newtype Perturb = Perturb [Word8]
    deriving (Show,Semigroup,Monoid)

instance IsList Perturb where
    type Item Perturb = Word8
    fromList = Perturb
    toList (Perturb x) = x

instance Arbitrary Perturb where
    arbitrary =
        do bs <- arbitrary
           if all (==0) bs
            then pure (Perturb (1:bs))
            else pure (Perturb bs)

newtype ByteString32 = ByteString32 S.ByteString deriving (Eq,Show)

instance Arbitrary ByteString32 where
  arbitrary = ByteString32 . S.pack <$> replicateM 32 arbitrary

newtype Message = Message S.ByteString deriving (Show)

instance Arbitrary Message where
  arbitrary = Message . S.pack <$> arbitrary

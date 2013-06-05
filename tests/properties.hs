{-# LANGUAGE OverloadedStrings #-}

module Main where

import Test.QuickCheck

import Crypto.Salty

import Data.Word
import qualified Data.ByteString as S
import qualified Data.Vector.Storable as V

import Control.Applicative
import Control.Monad

-- | Encryption can be decrypted
secretBoxRightInverseProp :: V.Vector Word8 -> V.Vector Word8 -> Message -> Bool
secretBoxRightInverseProp k n (Message bs) =
  Just bs == (toBS <$> secretboxOpen k n (secretbox k n (fromBS bs)))

-- | Encryption cannot be decrypted if the ciphertext is perturbed
secretBoxRightInverseFailureProp :: V.Vector Word8 -> V.Vector Word8 -> Message -> Bool
secretBoxRightInverseFailureProp k n (Message bs) =
  Nothing == (toBS <$> secretboxOpen k n (V.reverse $ secretbox k n (fromBS bs)))

-- | Encryption cannot be decrypted with a different key
secretBoxCannotDecryptKeyProp
  :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8 -> Message -> Bool
secretBoxCannotDecryptKeyProp k1 k2 n (Message bs) =
  Nothing == (toBS <$> secretboxOpen k2 n (secretbox k1 n (fromBS bs)))

-- | Encryption cannot be decrypted with a different nonce
secretBoxCannotDecryptNonceProp
  :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8 -> Message -> Bool
secretBoxCannotDecryptNonceProp k n1 n2 (Message bs) =
  Nothing == (toBS <$> secretboxOpen k n2 (secretbox k n1 (fromBS bs)))

testSecretBox :: IO ()
testSecretBox = do
  k1 <- newSecretBoxKey
  k2 <- newSecretBoxKey
  n1 <- newSecretBoxNonce
  n2 <- newSecretBoxNonce
  qc (secretBoxRightInverseProp k1 n1)
  qc (secretBoxRightInverseFailureProp k1 n1)
  qc (secretBoxCannotDecryptKeyProp   k1 k2 n1)
  qc (secretBoxCannotDecryptNonceProp k1 n1 n2)

main :: IO ()
main = do
  -- Use a few different key/nonce pairs
  testSecretBox >> testSecretBox >> testSecretBox



-- Some helpers

qc :: Testable a => a -> IO ()
qc = quickCheck

fromBS :: S.ByteString -> V.Vector Word8
fromBS = V.fromList . S.unpack

toBS ::  V.Vector Word8 -> S.ByteString
toBS = S.pack . V.toList

newtype Message = Message S.ByteString
                deriving (Show)

instance Arbitrary Message where
  arbitrary = Message . S.intercalate " " <$> listOf (oneof [
    return "word",
    return "other word"
    ])
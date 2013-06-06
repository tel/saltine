{-# LANGUAGE OverloadedStrings #-}

module SecretBoxProperties (
  testSecretBox
  ) where

import Util

import qualified Crypto.Saltine.Internal.SecretBox as SB

import Data.Word
import qualified Data.Vector.Storable as V

import Control.Applicative



-- | Ciphertext can be decrypted
rightInverseProp :: V.Vector Word8 -> V.Vector Word8 -> Message -> Bool
rightInverseProp k n (Message bs) =
  Just bs == (toBS <$> SB.secretboxOpen k n (SB.secretbox k n (fromBS bs)))

-- | Ciphertext cannot be decrypted if the ciphertext is perturbed
rightInverseFailureProp :: V.Vector Word8 -> V.Vector Word8 -> Message -> Bool
rightInverseFailureProp k n (Message bs) =
  Nothing == (toBS <$> SB.secretboxOpen k n (V.reverse $ SB.secretbox k n (fromBS bs)))

-- | Ciphertext cannot be decrypted with a different key
cannotDecryptKeyProp
  :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8 -> Message -> Bool
cannotDecryptKeyProp k1 k2 n (Message bs) =
  Nothing == (toBS <$> SB.secretboxOpen k2 n (SB.secretbox k1 n (fromBS bs)))

-- | Ciphertext cannot be decrypted with a different nonce
cannotDecryptNonceProp
  :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8 -> Message -> Bool
cannotDecryptNonceProp k n1 n2 (Message bs) =
  Nothing == (toBS <$> SB.secretboxOpen k n2 (SB.secretbox k n1 (fromBS bs)))

testSecretBox :: IO ()
testSecretBox = do
  k1 <- SB.newKey
  k2 <- SB.newKey
  n1 <- SB.newNonce
  n2 <- SB.newNonce
  qc (rightInverseProp k1 n1)
  qc (rightInverseFailureProp k1 n1)
  qc (cannotDecryptKeyProp   k1 k2 n1)
  qc (cannotDecryptNonceProp k1 n1 n2)

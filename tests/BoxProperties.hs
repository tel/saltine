{-# LANGUAGE OverloadedStrings #-}

module BoxProperties (
  testBox
  ) where

import Util

import qualified Crypto.Saltine.Internal.Box as B

import Data.Word
import qualified Data.Vector.Storable as V

import Control.Applicative



-- | Encryption can be decrypted
rightInverseProp
  :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8
     -> Message -> Bool
rightInverseProp pk sk n (Message bs) =
  Just bs == (toBS <$> B.boxOpen pk sk n (B.box pk sk n (fromBS bs)))

-- | Encryption cannot be decrypted if the ciphertext is perturbed
rightInverseFailureProp
  :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8
     -> Message -> Bool
rightInverseFailureProp pk sk n (Message bs) =
  Nothing == (toBS <$> B.boxOpen pk sk n (V.reverse $ B.box pk sk n (fromBS bs)))

-- | Encryption cannot be decrypted with a different key
cannotDecryptKeyProp
  :: V.Vector Word8 -> V.Vector Word8
     -> V.Vector Word8 -> V.Vector Word8
     -> V.Vector Word8 -> Message -> Bool
cannotDecryptKeyProp pk1 sk1 pk2 sk2 n (Message bs) =
  Nothing == (toBS <$> B.boxOpen pk2 sk2 n (B.box pk1 sk1 n (fromBS bs)))

-- | Encryption cannot be decrypted with a different nonce
cannotDecryptNonceProp
  :: V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8 -> V.Vector Word8
     -> Message -> Bool
cannotDecryptNonceProp pk sk n1 n2 (Message bs) =
  Nothing == (toBS <$> B.boxOpen pk sk n2 (B.box pk sk n1 (fromBS bs)))

testBox :: IO ()
testBox = do
  (sk1, pk1) <- B.newKeypair
  (sk2, pk2) <- B.newKeypair
  n1 <- B.newNonce
  n2 <- B.newNonce
  qc (rightInverseProp pk1 sk1 n1)
  qc (rightInverseFailureProp pk1 sk1 n1)
  qc (cannotDecryptKeyProp pk1 sk1 pk2 sk2 n1)
  qc (cannotDecryptNonceProp pk1 sk1 n1 n2)

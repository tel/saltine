module Crypto.Saltine.Internal.Util where

import Foreign.C
import Foreign.Ptr
import Foreign.ForeignPtr
import System.IO.Unsafe
import Data.Word
import Data.Monoid
import qualified Data.Vector.Storable as V
import qualified Data.Vector.Storable.Mutable as VM
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Base16 as S16

import Crypto.Saltine.Class
import Data.STRef

foreign import ccall "randombytes_buf"
  c_randombytes_buf :: Ptr Word8 -> CInt -> IO ()

-- | Increments a 'V.Vector' with 0 as the least-significant index.
nudgeVector :: V.Vector Word8 -> V.Vector Word8
nudgeVector v = V.modify go v
  where go mv = do
          iref <- newSTRef 0
          loop iref mv
        loop iref mv = do
          i <- readSTRef iref
          if i < len
            then do val <- VM.read mv i
                    if val == maxBound
                       then do VM.write mv i minBound
                               modifySTRef iref succ
                               loop iref mv
                      else VM.write mv i (succ val)
            else return ()
        len = V.length v

-- | View an encodable thing as a hex string
ashex :: IsEncoding a => a -> S.ByteString
ashex a = case transcode a of
  Just bs -> S16.encode bs
  Nothing -> error "Crypto.Saltine.Util.ashex"

-- | A default kind of Show instance for any 'IsEncoding' type
ashexShow :: IsEncoding a => String -> a -> String
ashexShow name a = name ++ "{ashex = \"" ++ S8.unpack (ashex a) ++ "\"}"

-- | 0-pad a vector
pad :: (VM.Storable a, Num a) => Int -> V.Vector a -> V.Vector a
pad n = mappend (V.replicate n 0)

-- | Remove a 0-padding from a vector
unpad :: VM.Storable a => Int -> V.Vector a -> V.Vector a
unpad = V.drop

-- | Converts a C-convention errno to an Either
handleErrno :: CInt -> (a -> Either String a)
handleErrno err a = case err of
  0  -> Right a
  -1 -> Left "failed"
  n  -> Left ("unexpected error code: " ++ show n)

unsafeDidSucceed :: IO CInt -> Bool
unsafeDidSucceed = go . unsafePerformIO
  where go 0 = True
        go _ = False

-- | Convenience function for accessing constant C vectors
constVectors :: VM.Storable a => [V.Vector a] -> ([Ptr a] -> IO b) -> IO b
-- Manual unfold of: @constVectors = runContT . mapM (ContT . V.unsafeWith)@
constVectors = foldr (\v kk -> \k -> (V.unsafeWith v) (\a -> kk (\as -> k (a:as)))) ($ [])

-- | Slightly safer cousin to 'buildUnsafeCVector' that remains in the
-- 'IO' monad.
buildUnsafeCVector' :: VM.Storable a => Int -> (Ptr a -> IO b) -> IO (b, V.Vector a)
buildUnsafeCVector' n k = do
  buf <- mallocForeignPtrArray n
  b <- withForeignPtr buf k
  vec <- V.unsafeFreeze (VM.unsafeFromForeignPtr buf 0 n)
  return (b, vec)

-- | Extremely unsafe function, use with utmost care! Builds a new
-- Vector using a ccall which is given access to the raw underlying
-- pointer. Overwrites are UNCHECKED and 'unsafePerformIO' is used so
-- it's difficult to predict the timing of the 'Vector' creation.
buildUnsafeCVector :: VM.Storable a => Int -> (Ptr a -> IO b) -> (b, V.Vector a)
buildUnsafeCVector n = unsafePerformIO . buildUnsafeCVector' n

-- | Build a sized random 'V.Vector' using Sodium's bindings to
-- @/dev/urandom@.
randomVector :: Int -> IO (V.Vector Word8)
randomVector n = do
  (_, vec) <- buildUnsafeCVector' n (`c_randombytes_buf` fromIntegral n)
  return vec

-- | To prevent a dependency on package 'errors'
hush :: Either s a -> Maybe a
hush = either (const Nothing) Just
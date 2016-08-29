{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}

module BitStringToRandom (RndT, RndST, RndIO, Rnd, RndState, getRandomM, getRandom2M, runRndT, newRandomElementST, getRandomElement, randomElementsLength, replaceSeedM, addSeedM, getRandomByteStringM) where

import Control.Monad.Identity (Identity)
import Control.Monad.Primitive (PrimMonad, PrimState, primitive)
import Control.Monad.ST (ST)
import Control.Monad.Trans.Class (MonadTrans, lift)
import Control.Monad.Trans.State.Lazy (StateT, put, state, runStateT)
import Control.Parallel.Strategies (parMap, rpar, using, rseq)
import Data.Bits (shiftL, (.|.), xor)
import Data.STRef (STRef, newSTRef, readSTRef, writeSTRef)

import qualified Data.BitString as BS
import qualified Data.ByteString.Lazy as ByS
import qualified Data.Vector.Unboxed as V
import qualified Data.Vector.Unboxed.Mutable as VM

bitsNeeded :: Integer -> Integer
bitsNeeded x = (+) 1 $ floor $ logBase 2 (fromIntegral x)

convertBitStringToInteger = BS.foldl' convert' 0
  where
  convert' :: Integer -> Bool -> Integer
  convert' prev cur = (shiftL prev 1) .|. (case cur of True -> 1 ; False -> 0)

multipleBitstringsSplitAt i x = join' (split' x) [] []
 where
 split' = parMap rpar (\bs -> let (take,drop) = BS.splitAt i bs in (take `using` rseq, drop))
 join' [] takers droppers = (takers, droppers)
 join' (x:xs) takers droppers = let (newTake, newDrop) = x in join' xs (newTake:takers) (newDrop:droppers)

multipleBitstringsAssertLength _ [] = False
multipleBitstringsAssertLength len x = len' x
  where
  len' [] = True
  len' (x:xs) = if (BS.length x) == len
                   then len' xs
                   else False


getRandom :: Integer -> [BS.BitString] -> (Integer, [BS.BitString])
getRandom 0 x = (0, x)
getRandom max string = if has_error
                          then error "There was an error acquiring random data"
                          else if random <= max
                                  then (random, unused)
                                  else getRandom max unused
  where
    bitsNeeded' = bitsNeeded max
    has_error = not $ multipleBitstringsAssertLength (fromInteger bitsNeeded') used
    random = foldl (\i cur -> xor i $ convertBitStringToInteger cur) 0 used
    (used, unused) = multipleBitstringsSplitAt (fromIntegral bitsNeeded') string

getRandom2 :: Integer -> Integer -> [BS.BitString] -> (Integer, [BS.BitString])
getRandom2 a b string = getRandom2' (getRandom (max' - min') string)
  where
  min' = min a b
  max' = max a b
  getRandom2' (random, unused) = (random + min', unused)

getRandomByteString :: Integer -> [BS.BitString] -> (ByS.ByteString, [BS.BitString])
getRandomByteString 0 x = (ByS.pack [], x)
getRandomByteString len x = let (byte, newState) = getRandom 255 x ; (allBytes, lastState) = getRandomByteString (len - 1) newState in (ByS.cons (fromIntegral byte) allBytes, lastState)

newRandomElementST :: VM.Unbox a => [a] -> ST s (STRef s (V.Vector a))
newRandomElementST acc = newSTRef $ V.fromList acc

getRandomElement :: (V.Unbox a) => STRef s (V.Vector a) -> RndST s a
getRandomElement ref = do
  vec <- lift $ readSTRef ref
  vec' <- lift $ V.unsafeThaw vec
  let n = toInteger $ VM.length vec'
  j <- if n > 0 then getRandomM $ n - 1
                else error "Out of pixels"
  let j' = fromInteger j
  aa <- lift $ VM.read vec' 0
  ab <- lift $ VM.read vec' j'
  lift $ VM.write vec' j' aa
  vec'' <- lift $ V.unsafeFreeze vec'
  lift $ writeSTRef ref $ V.unsafeTail vec''
  return ab

randomElementsLength ref = do
  vec <- lift $ readSTRef ref
  return $ V.length vec

--fromIntegral
--realToFrac

type RndState = [BS.BitString]
newtype RndT m a = RndT
  { unRndT :: StateT RndState m a }
  deriving (Functor, Applicative, Monad, MonadTrans)

instance PrimMonad m => PrimMonad (RndT m) where
  type PrimState (RndT m) = PrimState m
  primitive = lift . primitive
  {-# INLINE primitive #-}

type RndST s a = RndT (ST s) a
type RndIO a = RndT IO a
type Rnd a = RndT Identity a

replaceSeedM :: Monad m => RndState -> RndT m ()
replaceSeedM s = RndT $ put s

addSeedM :: Monad m => RndState -> RndT m ()
addSeedM s = RndT $ state $ addSeedM s
  where
  addSeedM x y = ((),x ++ y)


getRandomM :: Monad m => Integer -> RndT m Integer
getRandomM x = RndT $ state $ getRandom x

getRandom2M :: Monad m => Integer -> Integer -> RndT m Integer
getRandom2M x y = RndT $ state $ getRandom2 x y

getRandomByteStringM :: Monad m => Integer -> RndT m ByS.ByteString
getRandomByteStringM x = RndT $ state $ getRandomByteString x

runRndT :: RndState -> RndT m a -> m (a, RndState)
runRndT rnd m = runStateT (unRndT m) rnd


{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts #-}

module BitStringToRandom (getRandom, getRandom2, RndT, RndST, RndIO, Rnd, getRandomM, getRandom2M, shuffleM, runRndT) where

import Data.Bits
import Control.Monad.Trans.State.Lazy
import Control.Monad.Trans.Class
import Control.Monad.ST
import Control.Monad.Identity
import qualified Data.Vector.Unboxed as V
import qualified Data.Vector.Unboxed.Mutable as VM
import qualified Data.BitString as BS

bitsNeeded :: Integer -> Integer
bitsNeeded x = (+) 1 $ floor $ logBase 2 (fromIntegral x)

convertBitStringToInteger = BS.foldl' convert' 0
  where
  convert' :: Integer -> Bool -> Integer
  convert' prev cur = (shiftL prev 1) .|. (case cur of True -> 1 ; False -> 0)

getRandom :: Integer -> BS.BitString -> (Integer, BS.BitString)
getRandom 0 x = (0, x)
getRandom max string = if has_error
                          then error "There was an error acquiring random data"
                          else if random <= max
                                  then (random, unused)
                                  else getRandom max unused
  where
    bitsNeeded' = bitsNeeded max
    has_error = (toInteger $ BS.length used) /= bitsNeeded'
    random = convertBitStringToInteger used
    (used, unused) = BS.splitAt (fromIntegral bitsNeeded') string

getRandom2 :: Integer -> Integer -> BS.BitString -> (Integer, BS.BitString)
getRandom2 a b string = getRandom2' (getRandom (max' - min') string)
  where
  min' = min a b
  max' = max a b
  getRandom2' (random, unused) = (random + min', unused)

-- Could I make this lazy?
shuffleM :: V.Unbox a => [a] -> RndST s [a]
shuffleM arr = do
    arr' <- lift $ V.unsafeThaw $ V.fromList arr
    let n = VM.length arr'
    forM [0..n-2] $ \i -> do
      j <- getRandom2M (toInteger i) (toInteger $ n - 1)
      let j' = fromIntegral j
      aa <- lift $ VM.read arr' i
      ab <- lift $ VM.read arr' j'
      lift $ VM.write arr' j' aa
      return ab

--fromIntegral
--realToFrac

type RndState = BS.BitString
newtype RndT m a = RndT
  { unRndT :: StateT RndState m a }
  deriving (Functor, Applicative, Monad, MonadTrans)


type RndST s a = RndT (ST s) a
type RndIO a = RndT IO a
type Rnd a = RndT Identity a

getRandomM :: Monad m => Integer -> RndT m Integer
getRandomM x = RndT $ state $ getRandom x

getRandom2M :: Monad m => Integer -> Integer -> RndT m Integer
getRandom2M x y = RndT $ state $ getRandom2 x y

runRndT :: RndState -> RndT m a -> m (a, RndState)
runRndT rnd m = runStateT (unRndT m) rnd


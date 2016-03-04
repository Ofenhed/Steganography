module PixelStream (getPixels, addPixelsEncryptionM, Pixel, EncryptedPixel) where

import BitStringToRandom (RndST, getRandomM)
import qualified Data.BitString as BS
import Control.Monad.ST
import Data.Traversable


data Pixel = Pixel { x :: Int,
                           y :: Int,
                           z :: Int } deriving (Show)

data EncryptedPixel = EncryptedPixel { pix :: Pixel, invertBit :: Bool } deriving (Show)

getPixels :: Int -> Int -> [Pixel]
getPixels x y = do
  x <- [0..x-1]
  y <- [0..y-1]
  z <- [0..2]
  return $ Pixel x y z

addPixelsEncryptionM :: [Pixel] -> RndST s [EncryptedPixel]
addPixelsEncryptionM pixels = do
  forM pixels $ \pixel -> do
    invertBit <- getRandomM 1
    let invertBit' = case invertBit of 1 -> True
                                       0 -> False
    return $ EncryptedPixel pixel invertBit'

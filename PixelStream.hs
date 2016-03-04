module PixelStream (getPixels, addPixelsEncryptionM, Pixel, EncryptedPixel) where

import BitStringToRandom (RndST, getRandomM)
import qualified Data.BitString as BS
import Control.Monad.ST
import Data.Traversable
import Data.Word (Word32, Word8)


type Pixel = (Word32, Word32, Word8)

data EncryptedPixel = EncryptedPixel { pix :: Pixel, invertBit :: Bool } deriving (Show)

getPixels :: Word32 -> Word32 -> [Pixel]
getPixels x y = do
  x <- [0..x-1] :: [Word32]
  y <- [0..y-1] :: [Word32]
  z <- [0..2] :: [Word8]
  return $ (x, y, z)

addPixelsEncryptionM :: [Pixel] -> RndST s [EncryptedPixel]
addPixelsEncryptionM pixels = do
  forM pixels $ \pixel -> do
    invertBit <- getRandomM 1
    let invertBit' = case invertBit of 1 -> True
                                       0 -> False
    return $ EncryptedPixel pixel invertBit'

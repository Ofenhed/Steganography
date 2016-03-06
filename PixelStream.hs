module PixelStream (getPixels, Pixel) where

import Data.Word (Word32, Word8)

type Pixel = (Word32, Word32, Word8)

getPixels :: Word32 -> Word32 -> [Pixel]
getPixels x y = do
  x <- [0..x-1] :: [Word32]
  y <- [0..y-1] :: [Word32]
  z <- [0..2] :: [Word8]
  return $ (x, y, z)

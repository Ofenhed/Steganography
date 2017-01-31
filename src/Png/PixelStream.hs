{-# LANGUAGE Safe #-}
module Png.PixelStream (getPixels, Pixel) where

import safe Data.Word (Word32, Word8)

type Pixel = (Word32, Word32, Word8)

getPixels :: Word32 -> Word32 -> Word8 -> [Pixel]
getPixels x y colorsCount = do
  x' <- [0..x-1] :: [Word32]
  y' <- [0..y-1] :: [Word32]
  z' <- [0..colorsCount-1] :: [Word8]
  return $ (x', y', z')

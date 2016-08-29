{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE Rank2Types #-}

module ImageFileHandler (readBits, readBytes, writeBits, writeBytes, writeBytes_, readBits_, writeBits_, getCryptoPrimitives, readSalt, readSalt_, pngDynamicMap, pngDynamicComponentCount) where

import BitStringToRandom (getRandomElement, RndST, getRandomM)
import PixelStream (Pixel)

import Codec.Picture.Png
import Codec.Picture.Types
import Control.Monad
import Control.Monad.Trans.Class
import Data.Bits
import Data.Word (Word8)
import qualified Data.BitString as BS
import qualified Data.ByteString.Lazy as ByS

data CryptoPrimitive = CryptoPrimitive (PixelStream.Pixel) (Bool) deriving (Show)
type CryptoStream = [CryptoPrimitive]

getCryptoPrimitives pixels count = do
  read <- forM [1..count] $ \_ -> do
    pixel <- getRandomElement pixels
    inv <- getRandomBoolM
    return $ CryptoPrimitive pixel inv
  return $ read

getRandomBoolM :: RndST s Bool
getRandomBoolM = do
  b <- getRandomM 1
  return $ case b of 1 -> True
                     0 -> False

getColorAt :: DynamicImage -> Int -> Int -> Int -> Pixel16
getColorAt (ImageY8 i) x y c = let g = pixelAt i x y in fromIntegral $ [g] !! c
getColorAt (ImageY16 i) x y c = let g = pixelAt i x y in [g] !! c
getColorAt (ImageYA8 i) x y c = let PixelYA8 g _ = pixelAt i x y in fromIntegral $ [g] !! c
getColorAt (ImageYA16 i) x y c = let PixelYA16 g _ = pixelAt i x y in [g] !! c
getColorAt (ImageRGB8 i) x y c = let PixelRGB8 r g b = pixelAt i x y in fromIntegral $ [r, g, b] !! c
getColorAt (ImageRGB16 i) x y c = let PixelRGB16 r g b = pixelAt i x y in [r, g, b] !! c
getColorAt (ImageRGBA8 i) x y c = let PixelRGBA8 r g b _ = pixelAt i x y in fromIntegral $ [r, g, b] !! c
getColorAt (ImageRGBA16 i) x y c = let PixelRGBA16 r g b _ = pixelAt i x y in [r, g, b] !! c
getColorAt _ _ _ _ = error "Unsupported image format"

pngDynamicMap :: (forall pixel . (Codec.Picture.Types.Pixel pixel, PngSavable pixel, Bits (PixelBaseComponent pixel)) => Image pixel -> a)
              -> DynamicImage -> a
pngDynamicMap f (ImageY8    i) = f i
pngDynamicMap f (ImageY16   i) = f i
pngDynamicMap f (ImageYA8   i) = f i
pngDynamicMap f (ImageYA16  i) = f i
pngDynamicMap f (ImageRGB8  i) = f i
pngDynamicMap f (ImageRGB16 i) = f i
pngDynamicMap f (ImageRGBA8 i) = f i
pngDynamicMap f (ImageRGBA16 i) = f i
pngDynamicMap _ _ = error "Unsupported image format"

pngDynamicComponentCount  :: DynamicImage -> Int
pngDynamicComponentCount (ImageYA8   i) = ((componentCount . \x -> pixelAt x 0 0) i) - 1
pngDynamicComponentCount (ImageYA16  i) = ((componentCount . \x -> pixelAt x 0 0) i) - 1
pngDynamicComponentCount (ImageRGBA8 i) = ((componentCount . \x -> pixelAt x 0 0) i) - 1
pngDynamicComponentCount (ImageRGBA16 i) = ((componentCount . \x -> pixelAt x 0 0) i) - 1
pngDynamicComponentCount x = pngDynamicMap (componentCount . \x -> pixelAt x 0 0) x

readBits_ primitives image = BS.fromList $ read primitives
  where
  read = map $ \p ->
    let CryptoPrimitive (x, y, c) inv = p
        x' = fromIntegral x
        y' = fromIntegral y
        c' = fromIntegral c
        result = (getColorAt image x' y' c') .&. 1
    in xor inv $ case result of
                      1 -> True
                      0 -> False

readSalt_ primitives image = ByS.pack $ read primitives
  where
  read = map $ \p ->
    let CryptoPrimitive (x, y, c) inv = p
        x' = fromIntegral x
        y' = fromIntegral y
        c' = fromIntegral c
        result = getColorAt image x' y' c'
        msb = fromIntegral $ shift result (-8) :: Word8
        lsb = fromIntegral $ result :: Word8
        result' = if msb /= 0
                     then msb
                     else lsb
    in if inv
          then complement result'
          else result'

writeBits_ primitives image bits = forM_ (zipWith (\p b -> (p, b)) primitives (BS.toList bits)) $ \(p, bit) -> do
    let CryptoPrimitive (x, y, c) inv = p
        x' = fromIntegral x
        y' = fromIntegral y
        newBit = case xor inv bit of True -> 1
                                     False -> 0
    pixel <- readPixel image x' y'
    let pixel' = mixWith (\color value _ ->
          if color == fromIntegral c
             then (value .&. (complement 1)) .|. newBit
             else value) pixel pixel
    writePixel image x' y' pixel'

writeBytes_ primitives image bytes = lift $ writeBits_ primitives image $ BS.bitStringLazy bytes

readBits pixels image count = do
  primitives <- getCryptoPrimitives pixels count
  return $ readBits_ primitives image

readBytes pixels image count = do
  a <- readBits pixels image $ count * 8
  return $ BS.realizeBitStringLazy a

readSalt pixels image count = do
  primitives <- getCryptoPrimitives pixels count
  return $ readSalt_ primitives image

writeBits pixels image bits = do
  primitives <- getCryptoPrimitives pixels $ BS.length bits
  lift $ writeBits_ primitives image bits

writeBytes pixels image bytes = writeBits pixels image $ BS.bitStringLazy bytes

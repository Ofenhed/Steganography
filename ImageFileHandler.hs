{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE Rank2Types #-}

module ImageFileHandler (readBits, readBytes, writeBits, writeBytes, writeBytes_, readBits_, writeBits_, getCryptoPrimitives, readSalt, pngDynamicMap, pngDynamicComponentCount, ImageFileHandlerExceptions(UnsupportedFormatException, DifferentBetweenSizeOfPrimitivesAndDataLength), bitsAvailable, bytesAvailable) where

import Crypto.RandomMonad (getRandomElement, RndST, getRandomM, randomElementsLength)
import Codec.Picture.Png (PngSavable)
import Control.Exception (throw, Exception)
import Control.Monad (forM, forM_)
import Control.Monad.Trans.Class (lift)
import Data.Bits (Bits, xor, shift, (.&.), complement, (.|.))
import Data.Typeable (Typeable)
import Data.Word (Word8)
import PixelStream (Pixel)

import qualified Codec.Picture.Types as I
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
                     _ -> error "Incorrent response from getRandomM"

data ImageFileHandlerExceptions = UnsupportedFormatException |
                                  DifferentBetweenSizeOfPrimitivesAndDataLength
                                  deriving (Show, Typeable)
instance Exception ImageFileHandlerExceptions

getColorAt :: I.DynamicImage -> Int -> Int -> Int -> I.Pixel16
getColorAt (I.ImageY8 i) x y c = let g = I.pixelAt i x y in fromIntegral $ [g] !! c
getColorAt (I.ImageY16 i) x y c = let g = I.pixelAt i x y in [g] !! c
getColorAt (I.ImageYA8 i) x y c = let I.PixelYA8 g _ = I.pixelAt i x y in fromIntegral $ [g] !! c
getColorAt (I.ImageYA16 i) x y c = let I.PixelYA16 g _ = I.pixelAt i x y in [g] !! c
getColorAt (I.ImageRGB8 i) x y c = let I.PixelRGB8 r g b = I.pixelAt i x y in fromIntegral $ [r, g, b] !! c
getColorAt (I.ImageRGB16 i) x y c = let I.PixelRGB16 r g b = I.pixelAt i x y in [r, g, b] !! c
getColorAt (I.ImageRGBA8 i) x y c = let I.PixelRGBA8 r g b _ = I.pixelAt i x y in fromIntegral $ [r, g, b] !! c
getColorAt (I.ImageRGBA16 i) x y c = let I.PixelRGBA16 r g b _ = I.pixelAt i x y in [r, g, b] !! c
getColorAt _ _ _ _ = throw UnsupportedFormatException

pngDynamicMap :: (forall pixel . (I.Pixel pixel, PngSavable pixel, Bits (I.PixelBaseComponent pixel)) => I.Image pixel -> a)
              -> I.DynamicImage -> a
pngDynamicMap f (I.ImageY8    i) = f i
pngDynamicMap f (I.ImageY16   i) = f i
pngDynamicMap f (I.ImageYA8   i) = f i
pngDynamicMap f (I.ImageYA16  i) = f i
pngDynamicMap f (I.ImageRGB8  i) = f i
pngDynamicMap f (I.ImageRGB16 i) = f i
pngDynamicMap f (I.ImageRGBA8 i) = f i
pngDynamicMap f (I.ImageRGBA16 i) = f i
pngDynamicMap _ _ = throw UnsupportedFormatException

pngDynamicComponentCount  :: I.DynamicImage -> Int
pngDynamicComponentCount (I.ImageYA8   i) = ((I.componentCount . \x -> I.pixelAt x 0 0) i) - 1
pngDynamicComponentCount (I.ImageYA16  i) = ((I.componentCount . \x -> I.pixelAt x 0 0) i) - 1
pngDynamicComponentCount (I.ImageRGBA8 i) = ((I.componentCount . \x -> I.pixelAt x 0 0) i) - 1
pngDynamicComponentCount (I.ImageRGBA16 i) = ((I.componentCount . \x -> I.pixelAt x 0 0) i) - 1
pngDynamicComponentCount x = pngDynamicMap (I.componentCount . \x -> I.pixelAt x 0 0) x

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
                      _ -> error "(_ & 1) returned something else than 0 or 1."

readSalt pixels image count = read [0..count-1] >>= return . ByS.pack
  where
  read = mapM $ \_ -> do
    [CryptoPrimitive (x, y, c) inv] <- getCryptoPrimitives pixels 1
    let x' = fromIntegral x
        y' = fromIntegral y
        c' = fromIntegral c
        result = getColorAt image x' y' c'
        msb = fromIntegral $ shift result (-8) :: Word8
        lsb = fromIntegral $ result :: Word8
        result' = if msb /= 0
                     then msb
                     else lsb
        result'' = if inv
                      then complement result'
                      else result'
    -- This will throw away bits until a number between 0 and result'' is
    -- found. This means that this function will not only return a salt,
    -- but also salt the current crypto stream by throwing away a random
    -- number a of bits.
    _ <- getRandomM $ fromIntegral result''
    return result''

writeBits_ primitives image bits = if length primitives >= (fromIntegral $ BS.length bits)
                                      then forM_ (zipWith (\p b -> (p, b)) primitives (BS.toList bits)) inner
                                      else error "Got more data that crypto primitives"
  where
  inner (p, bit) = do
    let CryptoPrimitive (x, y, c) inv = p
        x' = fromIntegral x
        y' = fromIntegral y
        newBit = case xor inv bit of True -> 1
                                     False -> 0
    pixel <- I.readPixel image x' y'
    let pixel' = I.mixWith (\color value _ ->
          if color == fromIntegral c
             then (value .&. (complement 1)) .|. newBit
             else value) pixel pixel
    I.writePixel image x' y' pixel'

writeBytes_ primitives image bytes = lift $ writeBits_ primitives image $ BS.bitStringLazy bytes

readBits pixels image count = do
  primitives <- getCryptoPrimitives pixels count
  return $ readBits_ primitives image

readBytes pixels image count = do
  a <- readBits pixels image $ count * 8
  return $ BS.realizeBitStringLazy a

writeBits pixels image bits = do
  primitives <- getCryptoPrimitives pixels $ BS.length bits
  lift $ writeBits_ primitives image bits

writeBytes pixels image bytes = writeBits pixels image $ BS.bitStringLazy bytes

bitsAvailable pixels = randomElementsLength pixels
bytesAvailable pixels = randomElementsLength pixels >>= \bits -> return $ quot bits 8

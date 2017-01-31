{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ExistentialQuantification #-}
module PngContainer where

import SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..))
import Control.Monad.ST (ST)
import qualified Codec.Picture.Types as I
import Data.Word (Word32, Word8)
import Codec.Picture.Png (PngSavable)
import Codec.Picture.Types (dynamicMap, imageHeight, imageWidth, thawImage, unsafeThawImage, unsafeFreezeImage)
import qualified Codec.Picture.Types as PT
import Codec.Picture.Png (decodePngWithMetadata, encodePngWithMetadata, decodePng)
import Crypto.RandomMonad (getRandomElement, RndST, getRandomM, randomElementsLength, RandomElementsListST())
import Data.Array.ST (STArray(), getBounds, writeArray, readArray)
import qualified Png.ImageFileHandler as A
import Crypto.RandomMonad (newRandomElementST)
import Data.Bits (Bits)
import qualified Data.ByteString.Lazy as LBS
import Codec.Picture.Metadata (Metadatas)

type Pixel = (Word32, Word32, Word8)

getPixels :: Word32 -> Word32 -> Word8 -> [Pixel]
getPixels x y colorsCount = do
  x' <- [0..x-1] :: [Word32]
  y' <- [0..y-1] :: [Word32]
  z' <- [0..colorsCount-1] :: [Word8]
  return $ (x', y', z')

type PixelInfo s = (RandomElementsListST s Pixel, Maybe (STArray s (Int, Int) [Bool]), Metadatas)

data PngImage s = PngImage I.DynamicImage (PixelInfo s)
data WritablePngImage s a = (PngSavable a, PT.Pixel a, Bits (PT.PixelBaseComponent a)) => WritablePngImage (I.MutableImage s a) (PixelInfo s)

instance SteganographyContainer (ST s) (PngImage s) where
  readSalt (PngImage i info) count = A.readSalt info i count
  readBits (PngImage i info) count = A.readBits info i (fromIntegral count)
  length _ = error "Not implemented"
  createContainer imagedata = case decodePngWithMetadata (LBS.toStrict imagedata) of
                                Right (dynamicImage, metadata) -> newRandomElementST [] >>= \element -> return $ Right $ PngImage dynamicImage (element, Nothing, metadata)
                                Left _ -> return $ Left Nothing

instance (PT.Pixel a) => WritableSteganographyContainer (ST s) (PngImage s) (WritablePngImage s a) where
  writeBits (WritablePngImage image info) = A.writeBits info image

  withSteganographyContainer (PngImage image info) func =
      A.pngDynamicMap
        (\img -> thawImage img >>= \thawed -> func (WritablePngImage thawed info)) image
  --unsafeWithSteganographyContainer (PngImage image info) func =
  --    A.pngDynamicMap
  --      (\img -> unsafeThawImage img >>= \thawed -> func (WritablePngImage thawed info)) image
--instance ReadableSteganographyContainer (ST s) (PngImage s) where
--  readBits (PngImage i info) count = A.readBits info i (fromIntegral count)
--
--  createReadContainer = error "Not implemented"

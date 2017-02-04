{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ExistentialQuantification #-}
module Png.PngContainer (PngImage(..)) where

import SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..))
import Control.Monad.ST (ST)
import qualified Codec.Picture.Types as I
import Data.Word (Word32, Word8)
import Codec.Picture.Png (PngSavable)
import Codec.Picture.Types (dynamicMap, imageHeight, imageWidth, thawImage, unsafeThawImage, unsafeFreezeImage, freezeImage)
import qualified Codec.Picture.Types as PT
import Codec.Picture.Png (decodePngWithMetadata, encodePngWithMetadata, decodePng)
import Crypto.RandomMonad (getRandomElement, RndT, getRandomM, randomElementsLength, RandomElementsListST())
import Data.Array.ST (STArray(), getBounds, writeArray, readArray)
import qualified Png.ImageFileHandler as A
import Crypto.RandomMonad (newRandomElementST)
import Data.Bits (Bits)
import qualified Data.ByteString.Lazy as LBS
import Codec.Picture.Metadata (Metadatas)
import Control.Monad.Trans.Class (lift)

type Pixel = (Word32, Word32, Word8)

getPixels :: Word32 -> Word32 -> Word8 -> [Pixel]
getPixels x y colorsCount = do
  x' <- [0..x-1] :: [Word32]
  y' <- [0..y-1] :: [Word32]
  z' <- [0..colorsCount-1] :: [Word8]
  return $ (x', y', z')

type PixelInfo s = (RandomElementsListST s Pixel, Maybe (STArray s (Int, Int) [Bool]), Metadatas)

data PngImage s = PngImage I.DynamicImage (PixelInfo s)
data WritablePngImage s pixel = (PT.Pixel pixel, PngSavable pixel, Bits (PT.PixelBaseComponent pixel)) => WritablePngImage (I.MutableImage s pixel) (PixelInfo s)

instance WritableSteganographyContainer s (WritablePngImage s a) [A.CryptoPrimitive] where
  getPrimitives (WritablePngImage image info) = A.getCryptoPrimitives info
  writeBitsP (WritablePngImage image info) prim bits = lift $ A.writeBits_ prim info image bits

instance SteganographyContainer s (PngImage s) where
  readSalt (PngImage i info) count = A.readSalt info i count
  readBits (PngImage i info) count = A.readBits info i (fromIntegral count)
  createContainer imagedata = case decodePngWithMetadata (LBS.toStrict imagedata) of
                                Right (dynamicImage, metadata) -> A.createCryptoState False dynamicImage >>= \(element, otherthing) -> return $ Right $ PngImage dynamicImage (element, otherthing, metadata)
                                Left _ -> return $ Left "Could not decode"

  bytesAvailable (PngImage i (elements, _, _)) = randomElementsLength elements >>= return . fromIntegral

  --unsafeWithSteganographyContainer (PngImage image info) func =
  --    A.pngDynamicMap
  --      (\img -> unsafeThawImage img >>= \thawed -> func $ WritablePngImage thawed info) image
  withSteganographyContainer (PngImage image info@(_, _, metadata)) func = A.pngDynamicMap (\img -> do
      thawed <- thawImage img
      result <- func $ WritablePngImage thawed info
      case result of
        Left err -> return $ Left err
        Right _ -> do
          frozen <- freezeImage thawed
          return $ Right $ encodePngWithMetadata metadata frozen) image

{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE RankNTypes #-}
module Container.LosslessImage.Png.PngContainer (PngImage(..), PngImageType(..)) where

import Codec.Picture.Metadata (Metadatas)
import Codec.Picture.Png (decodePngWithMetadata, encodePngWithMetadata)
import Codec.Picture.Png (PngSavable)
import Codec.Picture.Types (thawImage, unsafeThawImage, unsafeFreezeImage, freezeImage)
import Control.Monad.ST (ST)
import Control.Monad.Trans.Class (lift)
import Crypto.RandomMonad (randomElementsLength, RandomElementsListST(), RndST)
import Data.Array.ST (STArray())
import Data.Bits (Bits)
import Data.Word (Word32, Word8)
import Container.LosslessImage.ImageContainer (Pixel, getPixels)
import SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..), SteganographyContainerOptions(..))

import qualified Codec.Picture.Types as PT
import qualified Data.BitString as BiS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy as LBS
import qualified Container.LosslessImage.Png.ImageFileHandler as A

data WritablePngImage pixel s = (PT.Pixel pixel, PngSavable pixel, Bits (PT.PixelBaseComponent pixel)) => WritablePngImage (PT.MutableImage s pixel) (A.PixelInfo s)

instance WritableSteganographyContainer (WritablePngImage a) [A.CryptoPrimitive] where
  getPrimitives (WritablePngImage image info) = A.getCryptoPrimitives info
  writeBitsP (WritablePngImage image info) prim bits = lift $ A.writeBits_ prim info image bits

-- Slow PNG Handling
data PngImage s = PngImage PT.DynamicImage (A.PixelInfo s)
data PngImageType = PngImageSpawner
                  | PngImageSpawnerFast

instance SteganographyContainerOptions PngImageType PngImage where
  createContainer options imagedata = case decodePngWithMetadata (LBS.toStrict imagedata) of
                                Right (dynamicImage, metadata) -> A.createCryptoState (case options of PngImageSpawnerFast -> True ; PngImageSpawner -> False) dynamicImage >>= \(element, otherthing) -> return $ Right $ PngImage dynamicImage (element, otherthing, metadata)
                                Left _ -> return $ Left "Could not decode"

instance SteganographyContainer (PngImage) where
  readSalt (PngImage i info) count = A.readSalt info i count
  readBits (PngImage i info) count = A.readBits info i (fromIntegral count)

  bitsAvailable (PngImage i (elements, _, _)) = randomElementsLength elements >>= return . fromIntegral

  unsafeWithSteganographyContainer (PngImage image info@(_, _, metadata)) func = A.pngDynamicMap (\img -> do
      thawed <- unsafeThawImage img
      result <- func $ WritablePngImage thawed info
      case result of
        Left err -> return $ Left err
        Right _ -> do
          frozen <- unsafeFreezeImage thawed
          return $ Right $ encodePngWithMetadata metadata frozen) image

  withSteganographyContainer (PngImage image info@(_, _, metadata)) func = A.pngDynamicMap (\img -> do
      thawed <- thawImage img
      result <- func $ WritablePngImage thawed info
      case result of
        Left err -> return $ Left err
        Right _ -> do
          frozen <- freezeImage thawed
          return $ Right $ encodePngWithMetadata metadata frozen) image


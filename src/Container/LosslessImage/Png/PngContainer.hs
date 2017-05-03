{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE RankNTypes #-}
module Container.LosslessImage.Png.PngContainer (PngImage(..), PngImageType(..)) where

import Codec.Picture.Png (decodePngWithMetadata, encodePngWithMetadata)
import Codec.Picture.Png (PngSavable)
import Codec.Picture.Metadata (Metadatas)
import Codec.Picture.Types (thawImage, unsafeThawImage, unsafeFreezeImage, freezeImage)
import Control.Monad.ST (ST)
import Control.Monad.Trans.Class (lift)
import Crypto.RandomMonad (randomElementsLength, RandomElementsListST(), RndST)
import Data.Array.ST (STArray())
import Data.Bits (Bits, (.&.), complement, (.|.))
import Data.Word (Word32, Word8)
import Container.LosslessImage.ImageContainer (Pixel, getPixels, ImageContainer(..), MutableImageContainer(..))
import Container.LosslessImage.ImageHandler (PixelInfo)
import SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..), SteganographyContainerOptions(..))
import Container.LosslessImage.ImageHandler (createCryptoState)
import Container.LosslessImage.Png.ImageFileHandler (getColorAt, pngDynamicMap, pngDynamicComponentCount)
import Container.LosslessImage.ImageContainer (WithPixelInfoType(..), WithPixelInfoTypeM(..))
import Container.LosslessImage.ImageBindings ()

import qualified Codec.Picture.Types as PT
import qualified Data.BitString as BiS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy as LBS

-- Slow PNG Handling
data PngImage = PngImage PT.DynamicImage Metadatas
data PngImageType = PngImageSpawner
                  | PngImageSpawnerFast
data MutablePngImage pixel s = (PT.Pixel pixel, PngSavable pixel, Bits (PT.PixelBaseComponent pixel)) => MutablePngImage (Word32, Word32, Word8) (PT.MutableImage s pixel)


instance SteganographyContainerOptions PngImageType (WithPixelInfoType PngImage) where
  createContainer options imagedata = case decodePngWithMetadata (LBS.toStrict imagedata) of
                                Right (dynamicImage, metadata) -> createCryptoState (case options of PngImageSpawnerFast -> True ; PngImageSpawner -> False) (PngImage dynamicImage metadata) >>= \info -> return $ Right $ WithPixelInfoType (PngImage dynamicImage metadata) info
                                Left _ -> return $ Left "Could not decode"

instance ImageContainer (PngImage) where
  getBounds (PngImage img _) = (fromIntegral $ PT.dynamicMap PT.imageWidth img, fromIntegral $ PT.dynamicMap PT.imageHeight img, fromIntegral $ pngDynamicComponentCount img)
  getPixelLsb state coords = case (getPixel state coords) .&. 1 of 1 -> True ; 0 -> False
  getPixel (PngImage img _) (x, y, c) = fromIntegral $ getColorAt img (fromIntegral x) (fromIntegral y) (fromIntegral c)
  withThawedImage png@(PngImage image metadata) state func = pngDynamicMap (\img -> do
    thawed <- thawImage img
    result <- func $ WithPixelInfoTypeM (MutablePngImage (getBounds png) thawed) state
    case result of
      Left err -> return $ Left err
      Right _ -> do
        frozen <- freezeImage thawed
        return $ Right $ encodePngWithMetadata metadata frozen) image

instance MutableImageContainer (MutablePngImage px) where
  getBoundsM (MutablePngImage bounds _) = return bounds
  getPixelLsbM (MutablePngImage _ img@(PT.MutableImage { PT.mutableImageData = arr })) (x, y, c) = do
         let (x', y') = (fromIntegral x, fromIntegral y)
         originalPixel <- PT.readPixel img x' y'
         let changedPixel = PT.mixWith (\color value _ ->
               if color == fromIntegral c
                  then value .&. (complement 1)
                  else value) originalPixel originalPixel
         return $ originalPixel /= changedPixel

  setPixelLsb (MutablePngImage _ img) (x, y, c) b = do
         let (x', y') = (fromIntegral x, fromIntegral y)
         pixel <- PT.readPixel img x' y'
         let pixel' = PT.mixWith (\color value _ ->
               if color == fromIntegral c
                  then (value .&. (complement 1)) .|. (if b then 1 else 0)
                  else value) pixel pixel
         PT.writePixel img x' y' pixel'

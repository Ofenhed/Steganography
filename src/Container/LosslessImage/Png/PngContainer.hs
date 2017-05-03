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
import Data.Bits (Bits)
import Data.Word (Word32, Word8)
import Container.LosslessImage.ImageContainer (Pixel, getPixels, ImageContainer(..), MutableImageContainer(..))
import Container.LosslessImage.ImageHandler (PixelInfo)
import SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..), SteganographyContainerOptions(..))
import Container.LosslessImage.ImageHandler (createCryptoState)
import Container.LosslessImage.ImageBindings (WithPixelInfoType(..))

import qualified Codec.Picture.Types as PT
import qualified Data.BitString as BiS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy as LBS

-- Slow PNG Handling
data PngImage = PngImage PT.DynamicImage Metadatas
data MutablePngImage a s = MutablePngImage (PT.MutableImage a s)
data PngImageType = PngImageSpawner
                  | PngImageSpawnerFast
data WritablePngImage pixel s = (PT.Pixel pixel, PngSavable pixel, Bits (PT.PixelBaseComponent pixel)) => WritablePngImage (PT.MutableImage s pixel)


instance SteganographyContainerOptions PngImageType (WithPixelInfoType PngImage) where
  createContainer options imagedata = case decodePngWithMetadata (LBS.toStrict imagedata) of
                                Right (dynamicImage, metadata) -> createCryptoState (case options of PngImageSpawnerFast -> True ; PngImageSpawner -> False) (PngImage dynamicImage metadata) >>= \info -> return $ Right $ WithPixelInfoType (PngImage dynamicImage metadata) info
                                Left _ -> return $ Left "Could not decode"

instance ImageContainer (PngImage) where
  getBounds img = error "Not implemented"
  getPixelLsb img (x, y, c) = error "Not implemented"
  getPixel img (x, y, c) = error "Not implemnted"
  withThawedImage img func = error "Not implemented"

instance MutableImageContainer (WritablePngImage px) where
  getBoundsM img = error "Not implemented"
  setPixelLsb img (x, y, c) b = error "Not implemented"

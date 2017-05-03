{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE Trustworthy #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE RankNTypes #-}

module Container.LosslessImage.ImageContainer (ImageContainer(..), MutableImageContainer(..), Pixel, getPixels) where

import Data.BitString as BS
import safe Control.Monad.ST (ST)
import safe Data.Word (Word32, Word8)
import Data.ByteString.Lazy as LBS
import Crypto.RandomMonad (RndST)
import SteganographyContainer (WritableSteganographyContainer(..))

type Pixel = (Word32, Word32, Word8)

getPixels :: Word32 -> Word32 -> Word8 -> [Pixel]
getPixels x y colorsCount = do
  x' <- [0..x-1] :: [Word32]
  y' <- [0..y-1] :: [Word32]
  z' <- [0..colorsCount-1] :: [Word8]
  return $ (x', y', z')

-- Image Containers

class ImageContainer img where
  getBounds :: img -> (Word32, Word32, Word8)
  getPixelLsb :: img -> (Word32, Word32, Word8) -> Bool
  getPixel :: img -> (Word32, Word32, Word8) -> Word32
  withThawedImage :: img -> (forall p. WritableSteganographyContainer thawed p => thawed s -> RndST s (Either String ())) -> RndST s (Either String LBS.ByteString)
  unsafeWithThawedImage :: img -> (forall p. WritableSteganographyContainer thawed p => thawed s -> RndST s (Either String ())) -> RndST s (Either String LBS.ByteString)
  -- Defaults
  unsafeWithThawedImage = withThawedImage

class MutableImageContainer img where
  setPixelLsb :: img s -> (Word32, Word32, Word8) -> Bool -> ST s ()
  getBoundsM :: img s -> ST s (Word32, Word32, Word8)
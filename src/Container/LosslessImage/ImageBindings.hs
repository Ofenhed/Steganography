{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Container.LosslessImage.ImageBindings where

import Container.LosslessImage.ImageContainer (ImageContainer(..), MutableImageContainer(..), WithPixelInfoTypeM(..), WithPixelInfoType(..))
import Container.LosslessImage.ImageHandler (CryptoStream, getCryptoPrimitives, readSalt, readBits, writeBits_)
import Crypto.RandomMonad (randomElementsLength)
import SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..), SteganographyContainerOptions(..))

import Control.Monad.Trans.Class (lift)

instance MutableImageContainer thawed => WritableSteganographyContainer (WithPixelInfoTypeM thawed) CryptoStream where
  getPrimitives (WithPixelInfoTypeM _ info) = getCryptoPrimitives info
  writeBitsP (WithPixelInfoTypeM image info) prim bits = lift $ writeBits_ prim info image bits

instance ImageContainer img => SteganographyContainer (WithPixelInfoType img) where
  readSalt (WithPixelInfoType img info) count = Container.LosslessImage.ImageHandler.readSalt info img count
  readBits (WithPixelInfoType img info) count = Container.LosslessImage.ImageHandler.readBits info img (fromIntegral count)

  bitsAvailable (WithPixelInfoType _ (list, _)) = randomElementsLength list >>= return . fromIntegral

  withSteganographyContainer (WithPixelInfoType image state) func = withThawedImage image state func


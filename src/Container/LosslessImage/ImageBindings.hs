{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Container.LosslessImage.ImageBindings where

import Container.LosslessImage.ImageContainer (ImageContainer(..), MutableImageContainer(..), Pixel, getPixels, WithPixelInfoTypeM(..), WithPixelInfoType(..))
import SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..), SteganographyContainerOptions(..))
import Crypto.RandomMonad (randomElementsLength)
import Container.LosslessImage.ImageHandler (CryptoPrimitive, CryptoStream, getCryptoPrimitives, readSalt, readBits, writeBits_, PixelInfo)
import Control.Monad.Trans.Class (lift)

instance MutableImageContainer thawed => WritableSteganographyContainer (WithPixelInfoTypeM thawed) CryptoStream where
  getPrimitives (WithPixelInfoTypeM _ info) = getCryptoPrimitives info
  writeBitsP (WithPixelInfoTypeM image info) prim bits = lift $ writeBits_ prim info image bits

---- Slow PNG Handling
--instance SteganographyContainerOptions PngImageType PngImage where
--  createContainer options imagedata = case decodePngWithMetadata (LBS.toStrict imagedata) of
--                                Right (dynamicImage, metadata) -> createCryptoState (case options of PngImageSpawnerFast -> True ; PngImageSpawner -> False) dynamicImage >>= \(element, otherthing) -> return $ Right $ PngImage dynamicImage (element, otherthing, metadata)
--                                Left _ -> return $ Left "Could not decode"

instance ImageContainer img => SteganographyContainer (WithPixelInfoType img) where
  readSalt (WithPixelInfoType img info) count = Container.LosslessImage.ImageHandler.readSalt info img count
  readBits (WithPixelInfoType img info) count = Container.LosslessImage.ImageHandler.readBits info img (fromIntegral count)

  bitsAvailable (WithPixelInfoType _ (list, _)) = randomElementsLength list >>= return . fromIntegral

  withSteganographyContainer (WithPixelInfoType image state) func = withThawedImage image state func


{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}

module Steganography (doEncrypt, doDecrypt, SteganographyExceptions(NotEnoughSpaceInImageException, NoHiddenDataFoundException)) where

import BitStringToRandom (runRndT, newRandomElementST, randomElementsLength)
import Codec.Picture.Png (decodePngWithMetadata, encodePngWithMetadata, decodePng)
import Codec.Picture.Types (dynamicMap, imageHeight, imageWidth, unsafeThawImage, unsafeFreezeImage)
import Control.Exception (throw, Exception)
import Control.Monad.ST (runST)
import Control.Monad.Trans.Class (lift)
import Control.Monad (when)
import Crypto.Pbkdf2 (hmacSha512Pbkdf2)
import CryptoState (createPublicKeyState, readPrivateKey, addAdditionalPrivateRsaState, addAdditionalPublicRsaState, createRandomStates)
import Data.Typeable (Typeable)
import Data.Word (Word8)
import HashedData (readUntilHash, writeAndHash)
import ImageFileHandler (pngDynamicMap, pngDynamicComponentCount)

import qualified Data.BitString as BS
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified PixelStream

data SteganographyExceptions = NotEnoughSpaceInImageException { maxSize :: Integer }
                               | NoHiddenDataFoundException
                               deriving (Show, Typeable)
instance Exception SteganographyExceptions

doEncrypt imageFile secretFile loops inputFile salt pkiFile = do
  a <- BS.readFile imageFile
  secret <- LBS.readFile secretFile
  input <- LBS.readFile inputFile
  publicKeyState <- createPublicKeyState pkiFile
  let Right (dynamicImage, metadata) = decodePngWithMetadata a
      (newImage,_) = runST $ runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops)] $ pngDynamicMap (\img -> unsafeThawImage img >>= runFunc input publicKeyState (dynamicImage, metadata) (fromIntegral $ LBS.length secret)) dynamicImage
  when (newImage /= LBS.empty) $ LBS.writeFile imageFile newImage
    where
    runFunc input publicKeyState (dynamicImage, metadatas) secretLength mutableImage = do
      let w = dynamicMap imageWidth dynamicImage
          h = dynamicMap imageHeight dynamicImage
      pixels <- lift $ newRandomElementST $ PixelStream.getPixels (fromIntegral w) (fromIntegral h) $ (fromIntegral $ pngDynamicComponentCount dynamicImage :: Word8)
      createRandomStates pixels dynamicImage salt secretLength
      addAdditionalPublicRsaState publicKeyState pixels mutableImage
      let dataLen = toInteger $ LBS.length input
      len <- randomElementsLength pixels
      let availLen = quot (toInteger len) 8
      if availLen < dataLen then throw $ NotEnoughSpaceInImageException availLen
                            else do
                              writeAndHash pixels mutableImage input
                              result <- unsafeFreezeImage mutableImage
                              return $ encodePngWithMetadata metadatas result

doDecrypt imageFile secretFile loops output salt pkiFile = do
  a <- BS.readFile imageFile
  secret <- LBS.readFile secretFile
  privateKey <- readPrivateKey pkiFile
  let Right dynamicImage = decodePng a
      w = dynamicMap imageWidth dynamicImage
      h = dynamicMap imageHeight dynamicImage
      (r,_) = runST $ runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops)] $ do
              pixels <- lift $ newRandomElementST $ PixelStream.getPixels (fromIntegral w) (fromIntegral h) $ (fromIntegral $ pngDynamicComponentCount dynamicImage :: Word8)
              createRandomStates pixels dynamicImage salt $ fromIntegral $ LBS.length secret
              addAdditionalPrivateRsaState privateKey pixels dynamicImage
              hiddenData <- readUntilHash pixels dynamicImage
              return $ Just hiddenData
  case r of Nothing -> throw NoHiddenDataFoundException
            Just x -> LBS.writeFile output x


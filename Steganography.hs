{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}

module Steganography (doEncrypt, doDecrypt) where

import BitStringToRandom (runRndT, newRandomElementST, randomElementsLength)
import Codec.Picture.Png (decodePngWithMetadata, encodePngWithMetadata)
import Codec.Picture.Types (dynamicMap, imageHeight, imageWidth, unsafeThawImage, unsafeFreezeImage)
import Control.Monad.ST (runST)
import Control.Monad.Trans.Class (lift)
import Control.Monad (when)
import Crypto.Pbkdf2 (hmacSha512Pbkdf2)
import CryptoState (createPublicKeyState, readPrivateKey, addAdditionalPrivateRsaState, addAdditionalPublicRsaState, createRandomStates)
import Data.Bits (shiftR, shiftL, (.|.))
import Data.Word (Word8, Word32)
import HashedData (readUntilHash, writeAndHash)
import ImageFileHandler (pngDynamicMap, pngDynamicComponentCount)

import qualified Data.BitString as BS
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified PixelStream

octets :: Word32 -> [Word8]
octets w = 
    [ fromIntegral (w `shiftR` 24)
    , fromIntegral (w `shiftR` 16)
    , fromIntegral (w `shiftR` 8)
    , fromIntegral w
    ]

fromOctets :: [Word8] -> Word32
fromOctets = Prelude.foldl accum 0
  where
    accum a o = (a `shiftL` 8) .|. fromIntegral o

toNum = fromInteger . toInteger

doEncrypt imageFile secretFile loops inputFile salt pkiFile = do
  a <- BS.readFile imageFile
  secret <- LBS.readFile secretFile
  input <- LBS.readFile inputFile
  publicKeyState <- createPublicKeyState pkiFile
  let Right (dynamicImage, metadata) = decodePngWithMetadata a
      (newImage,_) = runST $ runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops)] $ pngDynamicMap (\img -> unsafeThawImage img >>= runFunc input publicKeyState (dynamicImage, metadata)) dynamicImage
  when (newImage /= LBS.empty) $ LBS.writeFile imageFile newImage
    where
    runFunc input publicKeyState (dynamicImage, metadatas) mutableImage = do
      let w = dynamicMap imageWidth dynamicImage
          h = dynamicMap imageHeight dynamicImage
      pixels <- lift $ newRandomElementST $ PixelStream.getPixels (toNum w) (toNum h) $ (fromIntegral $ pngDynamicComponentCount dynamicImage :: Word8)
      createRandomStates pixels dynamicImage salt
      addAdditionalPublicRsaState publicKeyState pixels mutableImage
      let dataLen = toInteger $ LBS.length input
      writeAndHash pixels mutableImage input
      len <- randomElementsLength pixels
      let availLen = (quot (toInteger len) 8)
      if availLen < dataLen then error $ "The file doesn't fit in this image, the image can hold " ++ (show availLen) ++ " bytes maximum"
                            else do
                              writeAndHash pixels mutableImage input
                              result <- unsafeFreezeImage mutableImage
                              return $ encodePngWithMetadata metadatas result

doDecrypt imageFile secretFile loops output salt pkiFile = do
  a <- BS.readFile imageFile
  secret <- LBS.readFile secretFile
  privateKey <- readPrivateKey pkiFile
  let Right (dynamicImage, metadata) = decodePngWithMetadata a
      w = dynamicMap imageWidth dynamicImage
      h = dynamicMap imageHeight dynamicImage
      (r,_) = runST $ runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops)] $ do
              pixels <- lift $ newRandomElementST $ PixelStream.getPixels (toNum w) (toNum h) $ (fromIntegral $ pngDynamicComponentCount dynamicImage :: Word8)
              createRandomStates pixels dynamicImage salt
              addAdditionalPrivateRsaState privateKey pixels dynamicImage
              hiddenData <- readUntilHash pixels dynamicImage
              return $ Just hiddenData
  case r of Nothing -> putStrLn "No hidden data found"
            Just x -> LBS.writeFile output x


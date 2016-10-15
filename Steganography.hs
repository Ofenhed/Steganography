{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}

module Steganography (doEncrypt, doDecrypt, SteganographyExceptions(..)) where

import BitStringToRandom (runRndT, newRandomElementST)
import Codec.Picture.Png (decodePngWithMetadata, encodePngWithMetadata, decodePng)
import Codec.Picture.Types (dynamicMap, imageHeight, imageWidth, unsafeThawImage, unsafeFreezeImage)
import Control.Exception (throw, Exception)
import Control.Monad.ST (runST)
import Control.Monad.Trans.Class (lift)
import Control.Monad (when)
import Crypto.Pbkdf2 (hmacSha512Pbkdf2)
import CryptoState (createPublicKeyState, readPrivateKey, addAdditionalPrivatePkiState, addAdditionalPublicPkiState, createRandomStates, createSignatureState, createVerifySignatureState, addSignature, verifySignature)
import Data.Typeable (Typeable)
import Data.Word (Word8)
import HashedData (readUntilHash, writeAndHash)
import ImageFileHandler (pngDynamicMap, pngDynamicComponentCount, bytesAvailable)

import qualified Data.BitString as BS
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified PixelStream

data SteganographyExceptions = NotEnoughSpaceInImageException { maxSize :: Int }
                               | NoHiddenDataFoundException
                               | FoundDataButNoValidSignature
                               deriving (Show, Typeable)
instance Exception SteganographyExceptions

doEncrypt imageFile secretFile loops inputFile salt pkiFile signFile = do
  a <- BS.readFile imageFile
  secret <- LBS.readFile secretFile
  input <- LBS.readFile inputFile
  publicKeyState <- createPublicKeyState pkiFile
  signState <- createSignatureState signFile
  let Right (dynamicImage, metadata) = decodePngWithMetadata a
      (newImage,_) = runST $ runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops)] $ pngDynamicMap (\img -> unsafeThawImage img >>= runFunc input publicKeyState signState (dynamicImage, metadata) (fromIntegral $ LBS.length secret)) dynamicImage
  when (newImage /= LBS.empty) $ LBS.writeFile imageFile newImage
    where
    runFunc input publicKeyState signState (dynamicImage, metadatas) secretLength mutableImage = do
      let w = dynamicMap imageWidth dynamicImage
          h = dynamicMap imageHeight dynamicImage
      pixels <- lift $ newRandomElementST $ PixelStream.getPixels (fromIntegral w) (fromIntegral h) $ (fromIntegral $ pngDynamicComponentCount dynamicImage :: Word8)
      createRandomStates pixels dynamicImage salt secretLength
      addAdditionalPublicPkiState publicKeyState pixels mutableImage
      let dataLen = LBS.length input
      availLen <- bytesAvailable pixels
      if (fromIntegral availLen) < (fromIntegral dataLen) then throw $ NotEnoughSpaceInImageException availLen
                            else do
                              hash <- writeAndHash pixels mutableImage input
                              addSignature signState hash pixels mutableImage
                              result <- unsafeFreezeImage mutableImage
                              return $ encodePngWithMetadata metadatas result

doDecrypt imageFile secretFile loops output salt pkiFile signFile = do
  a <- BS.readFile imageFile
  secret <- LBS.readFile secretFile
  privateKey <- readPrivateKey pkiFile
  verifySignState <- createVerifySignatureState signFile
  let Right dynamicImage = decodePng a
      w = dynamicMap imageWidth dynamicImage
      h = dynamicMap imageHeight dynamicImage
      (r,_) = runST $ runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops)] $ do
              pixels <- lift $ newRandomElementST $ PixelStream.getPixels (fromIntegral w) (fromIntegral h) $ (fromIntegral $ pngDynamicComponentCount dynamicImage :: Word8)
              createRandomStates pixels dynamicImage salt $ fromIntegral $ LBS.length secret
              addAdditionalPrivatePkiState privateKey pixels dynamicImage
              hiddenData <- readUntilHash pixels dynamicImage
              case hiddenData of
                   Nothing -> return Nothing
                   Just (d, hash) -> do
                     verify <- verifySignature verifySignState (LBS.toStrict hash) pixels dynamicImage
                     return $ Just (d, verify)
  case r of Nothing -> throw NoHiddenDataFoundException
            Just (x, Nothing) -> LBS.writeFile output x
            Just (x, Just verified) -> if verified
                                          then LBS.writeFile output x
                                          else throw FoundDataButNoValidSignature

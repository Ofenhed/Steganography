{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}

module Steganography (doEncrypt, doDecrypt, SteganographyExceptions(..)) where

import CryptoState (createPublicKeyState, readPrivateKey, addAdditionalPrivatePkiState, addAdditionalPublicPkiState, createRandomStates, createSignatureState, createVerifySignatureState, addSignature, verifySignature)
import HashedData (readUntilHash, writeAndHash)
import ImageFileHandler (pngDynamicMap, pngDynamicComponentCount, bytesAvailable)
import Pbkdf2 (hmacSha512Pbkdf2)

import Codec.Picture.Png (decodePngWithMetadata, encodePngWithMetadata, decodePng)
import Codec.Picture.Types (dynamicMap, imageHeight, imageWidth, unsafeThawImage, unsafeFreezeImage)
import Control.Exception (throw, Exception)
import Control.Monad.ST (runST, ST())
import Control.Monad.Trans.Class (lift)
import Control.Monad (when)
import Crypto.RandomMonad (runRndT, newRandomElementST)
import Data.Array.ST (STArray(), newArray)
import Data.Maybe (isJust)
import Data.Typeable (Typeable)
import Data.Word (Word8)

import qualified EccKeys
import qualified Data.BitString as BS
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified PixelStream

data SteganographyExceptions = NotEnoughSpaceInImageException { maxSize :: Int }
                               | NoHiddenDataFoundException
                               | FoundDataButNoValidSignatureException
                               | TriedToEncryptSecretCertificateException
                               deriving (Show, Typeable)
instance Exception SteganographyExceptions

blockSecretCertificateAsInput inputFile = do
  inputCertificate <- EccKeys.readSecretKey $ EccKeys.SecretKeyPath inputFile
  when (isJust inputCertificate) $ throw TriedToEncryptSecretCertificateException

doEncrypt imageFile secretFile loops inputFile salt pkiFile signFile = do
  a <- BS.readFile imageFile
  secret <- LBS.readFile secretFile
  input <- LBS.readFile inputFile
  blockSecretCertificateAsInput inputFile
  publicKeyState <- createPublicKeyState pkiFile
  signState <- createSignatureState signFile
  let Right (dynamicImage, metadata) = decodePngWithMetadata a
      (newImage,_) = runST $ runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops)] $ pngDynamicMap (\img -> unsafeThawImage img >>= runFunc input publicKeyState signState (dynamicImage, metadata) (fromIntegral $ LBS.length secret)) dynamicImage
  when (newImage /= LBS.empty) $ LBS.writeFile imageFile newImage
    where
    runFunc input publicKeyState signState (dynamicImage, metadatas) secretLength mutableImage = do
      let w = dynamicMap imageWidth dynamicImage
          h = dynamicMap imageHeight dynamicImage
          colors = fromIntegral $ pngDynamicComponentCount dynamicImage :: Word8
      pixels'1 <- lift $ newRandomElementST $ PixelStream.getPixels (fromIntegral w) (fromIntegral h) colors
      pixels'2 <- lift $ (newArray ((0, 0, 0), (fromIntegral w - 1, fromIntegral h - 1, fromIntegral colors - 1)) False :: ST s (STArray s (Integer, Integer, Integer) Bool))
      let pixels = (pixels'1, pixels'2)
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
      colors = fromIntegral $ pngDynamicComponentCount dynamicImage :: Word8
      (r,_) = runST $ runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops)] $ do
              pixels'1 <- lift $ newRandomElementST $ PixelStream.getPixels (fromIntegral w) (fromIntegral h) colors
              pixels'2 <- lift $ (newArray ((0, 0, 0), (fromIntegral w - 1, fromIntegral h - 1, fromIntegral colors - 1)) False :: ST s (STArray s (Integer, Integer, Integer) Bool))
              let pixels = (pixels'1, pixels'2)
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
                                          else throw FoundDataButNoValidSignatureException

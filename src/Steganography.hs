{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}

--module Steganography (doEncrypt, doDecrypt, SteganographyExceptions(..)) where

import Codec.Picture.Png (decodePngWithMetadata, encodePngWithMetadata, decodePng)
import Codec.Picture.Types (dynamicMap, imageHeight, imageWidth, unsafeThawImage, unsafeFreezeImage)
import Control.Exception (throw, Exception)
import Control.Monad.ST (runST, ST())
import Control.Monad.ST.Unsafe (unsafeIOToST)
import Control.Monad.Trans.Class (lift)
import Control.Monad (when)
import Crypto.RandomMonad (runRndT, newRandomElementST)
import CryptoState (createPublicKeyState, readPrivateKey, addAdditionalPrivatePkiState, addAdditionalPublicPkiState, createRandomStates, createSignatureState, createVerifySignatureState, addSignature, verifySignature)
import Data.Array.ST (STArray(), newArray)
import Data.Maybe (isJust, fromJust)
import Data.Time (getCurrentTime, diffUTCTime, UTCTime, secondsToDiffTime)
import Data.Typeable (Typeable)
import Data.Word (Word8)
import HashedData (readUntilHash, writeAndHash)
import SteganographyContainer (storageAvailable)
import Pbkdf2 (hmacSha512Pbkdf2)
import Png.PngContainer (PngImage)
import SteganographyContainer (createContainer, withSteganographyContainer)

import qualified Data.BitString as BS
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified EccKeys

warnIfFasterThanSeconds = 5

data SteganographyExceptions = NotEnoughSpaceInImageException { maxSize :: Int }
                               | NoHiddenDataFoundException
                               | FoundDataButNoValidSignatureException
                               | TriedToEncryptSecretCertificateException
                               deriving (Show, Typeable)
instance Exception SteganographyExceptions

blockSecretCertificateAsInput inputData = do
  let inputCertificate = EccKeys.decodeSecretKey inputData
  when (isJust inputCertificate) $ throw TriedToEncryptSecretCertificateException

doEncrypt imageFile secretFile loops inputData salt pkiFile signFile fastMode = do
  let input = inputData
  blockSecretCertificateAsInput $ LBS.toStrict inputData
  publicKeyState <- createPublicKeyState pkiFile
  let signState = createSignatureState signFile
      --Right (dynamicImage, metadata) = decodePngWithMetadata imageFile
      (newImage,_) = runST $ do
        container <- createContainer imageFile :: ST s (Either String (PngImage s))
        case container of
          Left err -> error "Whatevs"
          Right container' -> do
            runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secretFile salt loops)] $ do
              createRandomStates container' salt (fromIntegral $ LBS.length secretFile)
              withSteganographyContainer container' $ \writer -> do
                do
                  timeBefore <- lift $ unsafeIOToST getCurrentTime
                  timeAfter <- lift $ unsafeIOToST getCurrentTime
                  let duration = diffUTCTime timeAfter timeBefore
                  lift $ unsafeIOToST $ putStrLn $ "Creating crypto context took " ++ (show $ duration)
                  when (duration < fromInteger warnIfFasterThanSeconds) $ lift $ unsafeIOToST $ putStrLn $ "This should take at least " ++ (show warnIfFasterThanSeconds) ++ " seconds. You should either change to a longer key or increase the iteration count."

                addAdditionalPublicPkiState publicKeyState writer
                let dataLen = LBS.length input
                availLen <- storageAvailable writer
                if isJust availLen && (fromIntegral $ fromJust availLen) < (fromIntegral dataLen)
                   then return $ Left $ "Trying to fid " ++ (show dataLen) ++ " bytes in an image with " ++ (show $ fromJust availLen) ++ " bytes available"
                   else do
                     hash <- writeAndHash writer input
                     addSignature signState hash writer
                     return $ Right ()
  return newImage
  --if (newImage /= LBS.empty) 
  --  then return $ Just newImage
  --  else return Nothing
--    where
--    runFunc input publicKeyState signState writer = do
--      do -- Unsafe operations in their own block to assure that nothing leaks
--        timeBefore <- lift $ unsafeIOToST getCurrentTime
--        timeAfter <- lift $ unsafeIOToST getCurrentTime
--        let duration = diffUTCTime timeAfter timeBefore
--        lift $ unsafeIOToST $ putStrLn $ "Creating crypto context took " ++ (show $ duration)
--        when (duration < fromInteger warnIfFasterThanSeconds) $ lift $ unsafeIOToST $ putStrLn $ "This should take at least " ++ (show warnIfFasterThanSeconds) ++ " seconds. You should either change to a longer key or increase the iteration count."
--
--      addAdditionalPublicPkiState publicKeyState writer
--      let dataLen = LBS.length input
--      availLen <- storageAvailable writer
--      if isJust availLen && (fromIntegral $ fromJust availLen) < (fromIntegral dataLen)
--         then return $ Left $ "Trying to fid " ++ (show dataLen) ++ " bytes in an image with " ++ (show $ fromJust availLen) ++ " bytes available"
--         else do
--           hash <- writeAndHash writer input
--           addSignature signState hash writer
--           return $ Right ()

--doDecrypt imageFile secretFile loops salt pkiFile signFile = do
--  verifySignState <- createVerifySignatureState signFile
--  let privateKey = readPrivateKey pkiFile
--      Right dynamicImage = decodePng imageFile
--      w = dynamicMap imageWidth dynamicImage
--      h = dynamicMap imageHeight dynamicImage
--      colors = fromIntegral $ pngDynamicComponentCount dynamicImage :: Word8
--      (r,_) = runST $ runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secretFile salt loops)] $ do
--              pixels'1 <- lift $ newRandomElementST $ PixelStream.getPixels (fromIntegral w) (fromIntegral h) colors
--              let pixels = (pixels'1, Nothing)
--              createRandomStates pixels dynamicImage salt $ fromIntegral $ LBS.length secretFile
--              addAdditionalPrivatePkiState privateKey pixels dynamicImage
--              hiddenData <- readUntilHash pixels dynamicImage
--              case hiddenData of
--                   Nothing -> return Nothing
--                   Just (d, hash) -> do
--                     verify <- verifySignature verifySignState (LBS.toStrict hash) pixels dynamicImage
--                     return $ Just (d, verify)
--  case r of Nothing -> throw NoHiddenDataFoundException
--            Just (x, Nothing) -> return $ Just x
--            Just (x, Just verified) -> if verified
--                                          then return $ Just x
--                                          else throw FoundDataButNoValidSignatureException

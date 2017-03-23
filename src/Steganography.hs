module Steganography (doEncrypt, doDecrypt, SteganographyExceptions(..)) where

import Codec.Picture.Png (decodePngWithMetadata, encodePngWithMetadata, decodePng)
import Codec.Picture.Types (dynamicMap, imageHeight, imageWidth, unsafeThawImage, unsafeFreezeImage)
import Control.Exception (throw, Exception)
import Control.Monad.ST (runST, ST())
import Control.Monad.ST.Unsafe (unsafeIOToST)
import Control.Monad.Trans.Class (lift)
import Control.Monad (when)
import Crypto.RandomMonad (newRandomElementST)
import CryptoContainer (EncryptionContainer(..), DecryptionContainer(..), CryptoContainer(..))
--import CryptoState (createPublicKeyState, readPrivateKey, addAdditionalPrivatePkiState, addAdditionalPublicPkiState, createRandomStates, createSignatureState, createVerifySignatureState, addSignature, verifySignature)
import DefaultCryptoState (DefaultCryptoState(..))
import Data.Array.ST (STArray(), newArray)
import Data.Maybe (isJust, fromJust)
import Data.Time (getCurrentTime, diffUTCTime, UTCTime, secondsToDiffTime)
import Data.Typeable (Typeable)
import Data.Word (Word8)
import HashedData (readUntilHash, writeAndHash)
import Pbkdf2 (hmacSha512Pbkdf2)
import Png.PngContainer (PngImage, PngImageType)
import SteganographyContainer (createContainer, withSteganographyContainer, SteganographyContainerOptions, storageAvailableBytes)

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

doEncrypt containerType cryptoContainer hashedDataContainer imageFile inputData = do
  let input = inputData
  blockSecretCertificateAsInput $ LBS.toStrict inputData

  return $ runST $ do
        container <- createContainer containerType imageFile
        case container of
          Left err -> return $ Left $ "Could not read image file"
          Right container' -> do
            runCrypto cryptoContainer $ do
              do -- Seperate context for IO operations
                timeBefore <- lift $ unsafeIOToST getCurrentTime
                initSymmetricCrypto cryptoContainer container'
                timeAfter <- lift $ unsafeIOToST getCurrentTime
                let duration = diffUTCTime timeAfter timeBefore
                lift $ unsafeIOToST $ putStrLn $ "Creating crypto context took " ++ (show $ duration)
                when (duration < fromInteger warnIfFasterThanSeconds) $
                  lift $ unsafeIOToST $
                  putStrLn $ "This should take at least " ++
                  (show warnIfFasterThanSeconds) ++ " seconds. You should either change to a longer key or increase the iteration count."

              withSteganographyContainer container' $ \writer -> do
                initAsymmetricEncrypter cryptoContainer writer
                let dataLen = LBS.length input
                availLen <- storageAvailableBytes writer
                if isJust availLen && (fromIntegral $ fromJust availLen) < (fromIntegral dataLen)
                   then return $ Left $
                        "Trying to fid " ++ (show dataLen) ++
                        " bytes in an image with " ++ (show $ fromJust availLen) ++ " bytes available"
                   else do
                     hash' <- writeAndHash hashedDataContainer cryptoContainer writer input
                     case hash' of
                       Left err -> return $ Left err
                       Right () -> return $ Right ()

doDecrypt containerType cryptoContainer hashedDataContainer imageFile = do
  let hiddenData = runST $ do
        container <- createContainer containerType imageFile
        case container of
          Left err -> return $ Left err
          Right reader -> do
            runCrypto cryptoContainer $ do
              initSymmetricCrypto cryptoContainer reader
              initAsymmetricDecrypter cryptoContainer reader
              hiddenData <- readUntilHash hashedDataContainer cryptoContainer reader
              case hiddenData of
                Left err -> return $ Left err
                Right Nothing -> return $ Left "No hidden data found"
                Right (Just (d, verified)) -> return $ Right (d, verified)
  case hiddenData of
    Left msg -> return $ Left msg
    Right (x, _) -> return $ Right x

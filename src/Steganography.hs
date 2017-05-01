module Steganography (doEncrypt, doDecrypt, SteganographyExceptions(..)) where

import Codec.Picture.Png (decodePngWithMetadata, encodePngWithMetadata, decodePng)
import Codec.Picture.Types (dynamicMap, imageHeight, imageWidth, unsafeThawImage, unsafeFreezeImage)
import Control.Exception (throw, Exception)
import Control.Monad.ST (runST, ST())
import Control.Monad.ST.Unsafe (unsafeIOToST)
import Control.Monad.Trans.Class (lift)
import Control.Monad (when)
import Crypto.RandomMonad (runRndT, newRandomElementST, RndStateList(RndStateListParallel))
import CryptoState (createPublicKeyState, readPrivateKey, addAdditionalPrivatePkiState, addAdditionalPublicPkiState, createRandomStates, createSignatureState, createVerifySignatureState, addSignature, verifySignature)
import Data.Array.ST (STArray(), newArray)
import Data.Maybe (isJust, fromJust)
import Data.Time (getCurrentTime, diffUTCTime, UTCTime, secondsToDiffTime)
import Data.Typeable (Typeable)
import Data.Word (Word8)
import HashedData (readUntilHash, writeAndHash)
import Pbkdf2 (hmacSha512Pbkdf2)
import Container.LosslessImage.Png.PngContainer (PngImage, PngImageType)
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

doEncrypt imageFile containerType secretFile loops inputData salt pkiFile signFile = do
  let input = inputData
  blockSecretCertificateAsInput $ LBS.toStrict inputData
  publicKeyState <- createPublicKeyState pkiFile
  let signState = createSignatureState signFile
      --Right (dynamicImage, metadata) = decodePngWithMetadata imageFile
      newImage = runST $ do
        container <- createContainer containerType imageFile
        case container of
          Left err -> return $ Left $ "Could not read image file"
          Right container' -> do
            (result, _) <- runRndT (RndStateListParallel [(BS.bitStringLazy $ hmacSha512Pbkdf2 secretFile salt loops)]) $ do
              do -- Seperate context for IO operations
                timeBefore <- lift $ unsafeIOToST getCurrentTime
                createRandomStates container' salt (fromIntegral $ LBS.length secretFile)
                timeAfter <- lift $ unsafeIOToST getCurrentTime
                let duration = diffUTCTime timeAfter timeBefore
                lift $ unsafeIOToST $ putStrLn $ "Creating crypto context took " ++ (show $ duration)
                when (duration < fromInteger warnIfFasterThanSeconds) $ lift $ unsafeIOToST $ putStrLn $ "This should take at least " ++ (show warnIfFasterThanSeconds) ++ " seconds. You should either change to a longer key or increase the iteration count."
              withSteganographyContainer container' $ \writer -> do

                addAdditionalPublicPkiState publicKeyState writer
                let dataLen = LBS.length input
                availLen <- storageAvailableBytes writer
                if isJust availLen && (fromIntegral $ fromJust availLen) < (fromIntegral dataLen)
                   then return $ Left $ "Trying to fid " ++ (show dataLen) ++ " bytes in an image with " ++ (show $ fromJust availLen) ++ " bytes available"
                   else do
                     hash' <- writeAndHash writer input
                     case hash' of
                       Left err -> return $ Left err
                       Right hash -> do
                         signResult <- addSignature signState hash writer
                         case signResult of
                           Left err -> return $ Left err
                           Right () -> return $ Right ()
            return result
  return newImage

doDecrypt imageFile containerType secretFile loops salt pkiFile signFile = do
  verifySignState <- createVerifySignatureState signFile
  let privateKey = readPrivateKey pkiFile
      hiddenData = runST $ do
        container <- createContainer containerType imageFile
        case container of
          Left err -> error "" -- TODO: Make sure this compiles with Left
          Right reader -> do
            (result, _) <- runRndT (RndStateListParallel [(BS.bitStringLazy $ hmacSha512Pbkdf2 secretFile salt loops)]) $ do
              createRandomStates reader salt $ fromIntegral $ LBS.length secretFile
              addAdditionalPrivatePkiState privateKey reader
              hiddenData <- readUntilHash reader
              case hiddenData of
                   Nothing -> return $ Left "No hidden data found"
                   Just (d, hash) -> do
                     verify <- verifySignature verifySignState (LBS.toStrict hash) reader
                     return $ Right (d, verify)
            return result
  case hiddenData of
            Left msg -> return $ Left msg
            Right (x, Nothing) -> return $ Right x
            Right (x, Just verified) -> if verified
                                           then return $ Right x
                                           else return $ Left "Found data but the signature was invalid"

module HashedData (writeAndHash, readUntilHash) where

import CryptoContainer (EncryptionContainer(..), DecryptionContainer(..))
import HashedDataContainer (HashedDataContainer(..))
import SteganographyContainer (readBytes, writeBytes, writeBytesP, getPrimitives, bytesAvailable, WritableSteganographyContainer(..))

import Control.Monad.ST (ST)
import Data.Word (Word8)

import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as LC8

writeAndHash hashedDataContainer cryptoState writer input = do
  let blockSize = getHashSize hashedDataContainer
  hashPosition <- getPrimitivesBytes writer (fromIntegral $ blockSize)
  --hashSalt <- getRandomByteStringM $ fromIntegral $ blockSize
  hasher <- hasherInit hashedDataContainer
  case hasher of
    Left msg -> return $ Left msg
    Right hasher' -> do

      signer <- signerInit cryptoState
      case signer of
        Left err -> return $ Left err
        Right signer' -> do
          let writeAndHashRecursive input' =
                if LBS.length input' == 0
                   then hasherFinalize hashedDataContainer hasher' writer hashPosition
                   else do
                     let byte = LC8.head input'
                         bsByte = LC8.singleton byte
                     writeResult <- writeBytes writer bsByte
                     case writeResult of
                       Left str -> return $ Left str
                       Right () -> do
                         hStatus <- hasherUpdate hashedDataContainer hasher' byte
                         case hStatus of
                           Left msg -> return $ Left msg
                           Right () -> do
                             sStatus <- signerAdd cryptoState signer' bsByte
                             case sStatus of
                               Left msg -> return $ Left msg
                               Right () -> writeAndHashRecursive (LBS.tail input')
          result <- writeAndHashRecursive input
          case result of
            Left msg -> return $ Left $ "Could not write and hash: " ++ msg
            Right h1 -> signerFinalize cryptoState signer' writer

readUntilHash hashedDataContainer cryptoState reader = do
  let blockSize = getHashSize hashedDataContainer
  hash <- readBytes reader $ fromIntegral blockSize
  --hashSalt <- getRandomByteStringM $ fromIntegral blockSize
  --            hash' = initialize (LBS.toStrict hashSalt) :: Context SHA1
  hasher <- hasherInit hashedDataContainer

  case hasher of
    Left msg -> return $ Left msg
    Right hasher' -> do
      verifier <- verifierInit cryptoState
      case verifier of
        Left msg -> return $ Left msg
        Right verifier' -> do
          let readUntilHashMatch readData = do
                hashCorrect <- hasherCheck hashedDataContainer hasher' hash
                case hashCorrect of
                  Left msg -> return $ Left msg
                  Right True -> return $ Right $ Just (LBS.pack $ reverse readData)
                  Right False -> bytesAvailable reader >>= \bytesLeft ->
                     if bytesLeft == 0
                        then return $ Right Nothing
                        else do
                          b <- readBytes reader 1
                          hasherUpdate hashedDataContainer hasher' $ LC8.head b
                          verifierAdd cryptoState verifier' b
                          readUntilHashMatch (LBS.head b:readData)
          readStatus <- readUntilHashMatch []
          case readStatus of
            Left err -> return $ Left err
            Right Nothing -> return $ Right Nothing
            Right (Just d) -> do
              status <- verifierFinalize cryptoState verifier' reader
              case status of
                Left err -> return $ Left err
                Right Nothing -> return $ Right $ Just (d, False)
                Right (Just True) -> return $ Right $ Just (d, True)
                Right _ -> return $ Left "Data could not be verified"

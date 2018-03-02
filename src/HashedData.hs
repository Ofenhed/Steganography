module HashedData (writeAndHash, readUntilHash) where

import Control.Monad.ST (ST)
import Crypto.Hash (SHA1(..), SHA3_512(..), SHA512(..), Skein512_512(..), Blake2b_512(..), hashDigestSize, digestFromByteString, HashAlgorithm, hashBlockSize)
import Crypto.MAC.HMAC (Context, update, initialize, finalize, hmacGetDigest)
import Crypto.RandomMonad (getRandomByteStringM, RndST)
import Data.Bits (xor)
import Data.Word (Word8)
import SteganographyContainer (readBytes, writeBytes, writeBytesP, getPrimitives, bytesAvailable, WritableSteganographyContainer(..))

import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

data SignatureHash = SignatureHash (Context SHA3_512) (Context SHA512) (Context Skein512_512) (Context Blake2b_512)

createBigSignatureHash :: RndST s SignatureHash
createBigSignatureHash = do
  salt1 <- getRandomByteStringM $ fromIntegral $ hashBlockSize SHA3_512
  salt2 <- getRandomByteStringM $ fromIntegral $ hashBlockSize SHA512
  salt3 <- getRandomByteStringM $ fromIntegral $ hashBlockSize Skein512_512
  salt4 <- getRandomByteStringM $ fromIntegral $ hashBlockSize Blake2b_512

  return $ SignatureHash (initialize salt1)
                         (initialize salt2)
                         (initialize salt3)
                         (initialize salt4)

signatureUpdate (SignatureHash s1 s2 s3 s4) d = (SignatureHash s1' s2' s3' s4')
  where
    s1' = update s1 d
    s2' = update s2 d
    s3' = update s3 d
    s4' = update s4 d

signatureFinalize (SignatureHash s1 s2 s3 s4) = hash
  where
  hash = concat [BA.unpack s1', BA.unpack s2', BA.unpack s3', BA.unpack s4']
  s1' = finalize s1
  s2' = finalize s2
  s3' = finalize s3
  s4' = finalize s4

writeAndHash :: WritableSteganographyContainer a p => a s -> LBS.ByteString -> RndST s (Either String [Word8])
writeAndHash writer input = do
  let blockSize = hashBlockSize SHA1
  let digestSize = hashDigestSize SHA1
  hashPosition <- getPrimitives writer (fromIntegral $ 8 * digestSize)
  hashSalt <- getRandomByteStringM $ fromIntegral blockSize

  bigHashes <- createBigSignatureHash

  let hash' = initialize hashSalt :: Context SHA1
      writeAndHashRecursive input' h1 h2 = if LBS.length input' == 0
                                              then return $ Right $ (finalize h1, signatureFinalize h2)
                                              else do
                                                let byte = LBS.singleton $ LBS.head input'
                                                writeResult <- writeBytes writer byte
                                                case writeResult of
                                                  Left str -> return $ Left str
                                                  Right () -> do
                                                    macXorBytes <- getRandomByteStringM 1
                                                    let [macXorByte] = BS.unpack macXorBytes
                                                        macByte = LBS.map (\x -> xor x macXorByte) byte
                                                        macByte' = LBS.toStrict macByte
                                                        newHash = update h1 macByte'
                                                        newSign = signatureUpdate h2 $ LBS.toStrict byte
                                                    writeAndHashRecursive (LBS.tail input') newHash newSign
  result <- writeAndHashRecursive input hash' bigHashes
  case result of
    Left msg -> return $ Left $ "Could not write and hash: " ++ msg
    Right (h1, h2) -> do
      let hash = LBS.pack $ BA.unpack h1
      writeResult <- writeBytesP writer hashPosition hash
      case writeResult of
        Left msg -> return $ Left $ "Could not write hash: " ++ msg
        Right () -> return $ Right h2

readUntilHash reader = do
  let blockSize = hashBlockSize SHA1
  let digestSize = hashDigestSize SHA1
  hash <- readBytes reader $ fromIntegral digestSize
  hashSalt <- getRandomByteStringM $ fromIntegral blockSize
  bigHashes <- createBigSignatureHash

  let Just digest = digestFromByteString $ LBS.toStrict hash
      hash' = initialize hashSalt :: Context SHA1
      readUntilHashMatch h1 h2 readData = if (hmacGetDigest $ finalize h1) == digest
                                             then return $ Just (LBS.pack $ reverse readData, LBS.pack $ signatureFinalize h2)
                                             else bytesAvailable reader >>= \bytesLeft ->
                                               if bytesLeft == 0
                                                  then return Nothing
                                                  else do
                                                    b <- readBytes reader 1
                                                    macXorBytes <- getRandomByteStringM 1
                                                    let [macXorByte] = BS.unpack macXorBytes
                                                        macByte = LBS.map (\x -> xor x macXorByte) b
                                                        macByte' = LBS.toStrict macByte
                                                        newHash = update h1 macByte'
                                                        newSign = signatureUpdate h2 $ LBS.toStrict b
                                                    readUntilHashMatch newHash newSign (LBS.head b:readData)
  readUntilHashMatch hash' bigHashes []


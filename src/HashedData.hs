module HashedData (writeAndHash, readUntilHash) where

import Control.Monad.ST (ST)
import Crypto.Hash (SHA1(..), SHA3_512, SHA512, Skein512_512, Blake2b_512, hashDigestSize, digestFromByteString, HashAlgorithm)
import Crypto.MAC.HMAC (Context, update, initialize, finalize, hmacGetDigest)
import Crypto.RandomMonad (getRandomByteStringM, RndST)
import Data.Bits (xor)
import Data.Word (Word8)
import SteganographyContainer (readBytes, writeBytes, writeBytesP, getPrimitives, bytesAvailable, WritableSteganographyContainer(..))

import qualified Data.ByteArray as BA
import qualified Data.ByteString.Lazy as LBS

data SignatureHash = SignatureHash (Context SHA3_512) (Context SHA512) (Context Skein512_512) (Context Blake2b_512)

createBigSignatureHash :: RndST s SignatureHash
createBigSignatureHash = do
  salt1 <- getRandomByteStringM 4096
  salt2 <- getRandomByteStringM 4096
  salt3 <- getRandomByteStringM 4096
  salt4 <- getRandomByteStringM 4096

  return $ SignatureHash (initialize (LBS.toStrict salt1))
                         (initialize (LBS.toStrict salt2))
                         (initialize (LBS.toStrict salt3))
                         (initialize (LBS.toStrict salt4))

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

writeAndHash :: WritableSteganographyContainer s a p => a -> LBS.ByteString -> RndST s [Word8]
writeAndHash writer input = do
  let blockSize = hashDigestSize SHA1
  hashPosition <- getPrimitives writer (fromIntegral $ 8 * blockSize)
  hashSalt <- getRandomByteStringM $ fromIntegral blockSize

  bigHashes <- createBigSignatureHash

  let hash' = initialize (LBS.toStrict hashSalt) :: Context SHA1
      writeAndHashRecursive input' h1 h2 = if LBS.length input' == 0
                                              then return $ (finalize h1, signatureFinalize h2)
                                              else do
                                                let byte = LBS.singleton $ LBS.head input'
                                                writeBytes writer byte
                                                macXorBytes <- getRandomByteStringM 1
                                                let [macXorByte] = LBS.unpack macXorBytes
                                                    macByte = LBS.map (\x -> xor x macXorByte) byte
                                                    macByte' = LBS.toStrict macByte
                                                    newHash = update h1 macByte'
                                                    newSign = signatureUpdate h2 $ LBS.toStrict byte
                                                writeAndHashRecursive (LBS.tail input') newHash newSign
  (h1, h2) <- writeAndHashRecursive input hash' bigHashes
  let hash = LBS.pack $ BA.unpack h1
  writeBytesP writer hashPosition hash
  return h2

readUntilHash reader = do
  let blockSize = hashDigestSize SHA1
  hash <- readBytes reader $ fromIntegral blockSize
  hashSalt <- getRandomByteStringM $ fromIntegral blockSize
  bigHashes <- createBigSignatureHash

  let Just digest = digestFromByteString $ LBS.toStrict hash
      hash' = initialize (LBS.toStrict hashSalt) :: Context SHA1
      readUntilHashMatch h1 h2 readData = if (hmacGetDigest $ finalize h1) == digest
                                             then return $ Just (LBS.pack $ reverse readData, LBS.pack $ signatureFinalize h2)
                                             else bytesAvailable reader >>= \bytesLeft ->
                                               if bytesLeft == 0
                                                  then return Nothing
                                                  else do
                                                    b <- readBytes reader 1
                                                    macXorBytes <- getRandomByteStringM 1
                                                    let [macXorByte] = LBS.unpack macXorBytes
                                                        macByte = LBS.map (\x -> xor x macXorByte) b
                                                        macByte' = LBS.toStrict macByte
                                                        newHash = update h1 macByte'
                                                        newSign = signatureUpdate h2 $ LBS.toStrict b
                                                    readUntilHashMatch newHash newSign (LBS.head b:readData)
  readUntilHashMatch hash' bigHashes []


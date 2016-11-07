{-# LANGUAGE FlexibleContexts #-}

module HashedData (writeAndHash, readUntilHash) where

import Crypto.RandomMonad (getRandomByteStringM)
import Crypto.Hash (SHA1(..), hashDigestSize, digestFromByteString)
import Crypto.MAC.HMAC (Context, update, initialize, finalize, hmacGetDigest)
import Data.Bits (xor)
import ImageFileHandler (readBytes, writeBytes, writeBytes_, getCryptoPrimitives, bytesAvailable)

import qualified Data.ByteArray as BA
import qualified Data.ByteString.Lazy as LBS

writeAndHash pixels image input = do
  let blockSize = hashDigestSize SHA1
  hashPosition <- getCryptoPrimitives pixels (8 * blockSize)
  hashSalt <- getRandomByteStringM $ fromIntegral blockSize
  let hash' = initialize (LBS.toStrict hashSalt) :: Context SHA1
      writeAndHashRecursive input' h = if LBS.length input' == 0
                                          then return $ finalize h
                                          else do
                                            let byte = LBS.singleton $ LBS.head input'
                                            writeBytes pixels image byte
                                            macXorBytes <- getRandomByteStringM 1
                                            let [macXorByte] = LBS.unpack macXorBytes
                                                macByte = LBS.map (\x -> xor x macXorByte) byte
                                                newHash = update h $ LBS.toStrict macByte
                                            writeAndHashRecursive (LBS.tail input') newHash
  h <- writeAndHashRecursive input hash'
  let hash = LBS.pack $ BA.unpack h
  writeBytes_ hashPosition image hash
  return h

readUntilHash pixels image = do
  let blockSize = hashDigestSize SHA1
  hash <- readBytes pixels image blockSize
  hashSalt <- getRandomByteStringM $ fromIntegral blockSize
  let Just digest = digestFromByteString $ LBS.toStrict hash
      hash' = initialize (LBS.toStrict hashSalt) :: Context SHA1
      readUntilHashMatch h readData = if (hmacGetDigest $ finalize h) == digest
                                         then return $ Just (LBS.pack $ reverse readData, hash)
                                         else bytesAvailable pixels >>= \bytesLeft ->
                                           if bytesLeft == 0
                                              then return Nothing
                                              else do
                                                b <- readBytes pixels image 1
                                                macXorBytes <- getRandomByteStringM 1
                                                let [macXorByte] = LBS.unpack macXorBytes
                                                    macByte = LBS.map (\x -> xor x macXorByte) b
                                                    newHash = update h $ LBS.toStrict macByte
                                                readUntilHashMatch newHash (LBS.head b:readData)
  readUntilHashMatch hash' []


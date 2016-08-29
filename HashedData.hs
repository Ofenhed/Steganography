{-# LANGUAGE FlexibleContexts #-}

module HashedData (writeAndHash, readUntilHash) where

import BitStringToRandom (getRandomByteStringM)
import Crypto.Hash (Context, SHA1(..), hashDigestSize, hashUpdate, hashInit, hashFinalize, digestFromByteString)
import Data.Bits (xor)
import ImageFileHandler (readBytes, writeBytes, writeBytes_, getCryptoPrimitives)

import qualified Data.ByteArray as BA
import qualified Data.ByteString.Lazy as LBS

writeAndHash pixels image input = do
  hashPosition <- getCryptoPrimitives pixels (8 * (hashDigestSize SHA1))
  hashSalt <- getRandomByteStringM 256
  let hash' = hashUpdate (hashInit :: Context SHA1) $ LBS.toStrict hashSalt
      writeAndHashRecursive input' h = if LBS.length input' == 0
                                          then return $ hashFinalize h
                                          else do
                                            let byte = LBS.singleton $ LBS.head input'
                                            writeBytes pixels image byte
                                            macXorBytes <- getRandomByteStringM 1
                                            let [macXorByte] = LBS.unpack macXorBytes
                                                macByte = LBS.map (\x -> xor x macXorByte) byte
                                                newHash = hashUpdate h $ LBS.toStrict macByte
                                            writeAndHashRecursive (LBS.tail input') newHash
  h <- writeAndHashRecursive input hash'
  writeBytes_ hashPosition image (LBS.pack $ BA.unpack h)

readUntilHash pixels image = do
  hash <- readBytes pixels image (hashDigestSize SHA1)
  hashSalt <- getRandomByteStringM 256
  let Just digest = digestFromByteString $ LBS.toStrict hash
      hash' = hashUpdate (hashInit :: Context SHA1) $ LBS.toStrict hashSalt
      readUntilHashMatch h readData = if hashFinalize h == digest
                                         then return $ LBS.pack $ reverse readData
                                         else do
                                           b <- readBytes pixels image 1
                                           macXorBytes <- getRandomByteStringM 1
                                           let [macXorByte] = LBS.unpack macXorBytes
                                               macByte = LBS.map (\x -> xor x macXorByte) b
                                               newHash = hashUpdate h $ LBS.toStrict macByte
                                           readUntilHashMatch newHash (LBS.head b:readData)
  readUntilHashMatch hash' []


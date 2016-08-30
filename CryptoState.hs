{-# LANGUAGE FlexibleContexts #-}

module CryptoState (createPublicKeyState, readPrivateKey, addAdditionalPrivateRsaState, addAdditionalPublicRsaState, createRandomStates) where

import AesEngine (createAes256RngState)
import BitStringToRandom (replaceSeedM, addSeedM, getRandomByteStringM)
import Codec.Picture.Types (imageWidth, imageHeight)
import Crypto.Hash (SHA3_256(..), hashDigestSize)
import Crypto.Pbkdf2 (hmacSha512Pbkdf2)
import Crypto.PubKey.RSA.Types (private_size, Error(MessageTooLong), public_size)
import Crypto.Random.Entropy (getEntropy)
import Data.Maybe (isNothing)
import ImageFileHandler (readBytes, writeBytes, readSalt, pngDynamicMap)

import qualified Crypto.PubKey.RSA.OAEP as OAEP
import qualified Data.BitString as BS
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified PemData (readPublicKey, readPrivateKey)

oaepParams = OAEP.defaultOAEPParams SHA3_256

readPrivateKey [] = return Nothing
readPrivateKey filename = do
  key <- PemData.readPrivateKey filename
  return $ key

createPublicKeyState filename = do
  privateKey <- PemData.readPublicKey filename
  if isNothing privateKey
     then return Nothing
     else do
       let Just a = privateKey
       seed <- getEntropy $ hashDigestSize $ OAEP.oaepHash oaepParams
       secret <- getEntropy $ public_size a
       return $ Just (BS.unpack seed, BS.unpack secret, a)

addAdditionalPrivateRsaState Nothing _ _ = return ()
addAdditionalPrivateRsaState (Just key) pixels image = do
  encrypted <- readBytes pixels image $ private_size key
  let Right decrypted = OAEP.decrypt Nothing oaepParams key (LBS.toStrict encrypted)
  salt <- getRandomByteStringM 256
  addSeedM [(BS.bitStringLazy $ hmacSha512Pbkdf2 (C8.fromStrict decrypted) salt 5)]

addAdditionalPublicRsaState Nothing _ _ = return ()
addAdditionalPublicRsaState (Just (seed, secret, key)) pixels image = do
  let encrypted = OAEP.encryptWithSeed (BS.pack seed) oaepParams key $ BS.pack secret
  case encrypted of
       Left MessageTooLong -> addAdditionalPublicRsaState (Just (seed, tail secret, key)) pixels image
       Right b -> do
         writeBytes pixels image $ LBS.fromStrict b
         salt <- getRandomByteStringM 256
         addSeedM [(BS.bitStringLazy $ hmacSha512Pbkdf2 (LBS.pack secret) salt 5)]

createRandomStates pixels image salt minimumEntropyBytes = do
  let width = pngDynamicMap imageWidth image
      height = pngDynamicMap imageHeight image
      imageSaltLength = quot (width*height) 10
  bigSalt <- readSalt pixels image $ imageSaltLength
  -- For the worst possible image, bigSalt will contain 1 bit of entropy
  -- per byte, since it's inverted by the inv variable from the PixelStream.
  extraSalt <- getRandomByteStringM $ max 0 $ minimumEntropyBytes - (fromIntegral $ quot imageSaltLength 8)
  newPbkdfSecret <- getRandomByteStringM 256
  aesSecret1 <- getRandomByteStringM 32
  replaceSeedM [(BS.bitStringLazy $ hmacSha512Pbkdf2 newPbkdfSecret (LBS.concat [bigSalt, salt, extraSalt]) 5)]
  aesSecret2 <- getRandomByteStringM 32
  addSeedM $ createAes256RngState $ LBS.toStrict aesSecret1
  addSeedM $ createAes256RngState $ LBS.toStrict aesSecret2



{-# LANGUAGE FlexibleContexts #-}

module CryptoState (createPublicKeyState, readPrivateKey, addAdditionalPrivatePkiState, addAdditionalPublicPkiState, createRandomStates) where

import AesEngine (createAes256RngState)
import BitStringToRandom (replaceSeedM, addSeedM, getRandomByteStringM)
import Codec.Picture.Types (imageWidth, imageHeight)
import Control.Exception (Exception, throw)
import Crypto.Error (CryptoFailable(CryptoPassed))
import Crypto.Hash (SHA3_256(..), hashDigestSize)
import Crypto.Pbkdf2 (hmacSha512Pbkdf2)
import Crypto.PubKey.RSA.Types (private_size, Error(MessageTooLong), public_size)
import Crypto.Random.Entropy (getEntropy)
import Data.Maybe (isNothing, isJust, fromJust)
import Data.Typeable (Typeable)
import Data.Word (Word8)
import ImageFileHandler (readBytes, writeBytes, readSalt, pngDynamicMap)

import qualified Crypto.PubKey.Curve25519 as Curve
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import qualified Data.BitString as BS
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified EccKeys
import qualified PemData (readPublicKey, readPrivateKey)

oaepParams = OAEP.defaultOAEPParams SHA3_256

data CryptoStateException = CouldNotReadPkiFileException deriving (Show, Typeable)
instance Exception CryptoStateException

data PrivatePki = PrivatePkiRsa RSA.PrivateKey
                | PrivatePkiEcc Curve.SecretKey

data PublicPki = PublicPkiRsa ([Word8], [Word8], RSA.PublicKey)
               | PublicPkiEcc Curve.SecretKey Curve.PublicKey

readPrivateKey [] = return Nothing
readPrivateKey filename = do
  rsaKey <- PemData.readPrivateKey filename
  eccKey <- EccKeys.readSecretKey (EccKeys.SecretKeyPath filename)
  if isJust rsaKey
     then return $ Just $ PrivatePkiRsa $ fromJust rsaKey
     else if isJust eccKey
             then return $ Just $ PrivatePkiEcc $ fromJust eccKey
             else throw CouldNotReadPkiFileException

createPublicRsaKeyState filename = do
  privateKey <- PemData.readPublicKey filename
  if isNothing privateKey
     then return Nothing
     else do
       let Just a = privateKey
       seed <- getEntropy $ hashDigestSize $ OAEP.oaepHash oaepParams
       secret <- getEntropy $ public_size a
       return $ Just (BS.unpack seed, BS.unpack secret, a)

createPublicEccKeyState filename = do
  eccKey <- EccKeys.readPublicKey (EccKeys.PublicKeyPath filename)
  if isNothing eccKey
     then return Nothing
     else do
       secret <- EccKeys.generateSecretKey
       return $ Just $ PublicPkiEcc secret (fromJust eccKey)

createPublicKeyState [] = return Nothing
createPublicKeyState filename = do
  rsaState <- createPublicRsaKeyState filename
  eccKey <- createPublicEccKeyState filename
  if isJust rsaState
     then return $ Just $ PublicPkiRsa $ fromJust rsaState
     else if isJust eccKey
             then return eccKey
             else throw CouldNotReadPkiFileException

--------------------------------------------------------------------------------
addAdditionalPrivatePkiState Nothing _ _ = return ()

addAdditionalPrivatePkiState (Just (PrivatePkiRsa key)) pixels image = do
  encrypted <- readBytes pixels image $ private_size key
  let Right decrypted = OAEP.decrypt Nothing oaepParams key (LBS.toStrict encrypted)
  salt <- getRandomByteStringM 256
  addSeedM [(BS.bitStringLazy $ hmacSha512Pbkdf2 (C8.fromStrict decrypted) salt 5)]

addAdditionalPrivatePkiState (Just (PrivatePkiEcc key)) pixels image = do
  encryptedKey <- readBytes pixels image $ 32 -- ECC key size
  let CryptoPassed pubKey = Curve.publicKey $ LBS.toStrict encryptedKey
      key' = BS.pack $ BA.unpack $ Curve.dh pubKey key
  addSeedM $ createAes256RngState $ key'
--------------------------------------------------------------------------------
addAdditionalPublicPkiState Nothing _ _ = return ()

addAdditionalPublicPkiState (Just (PublicPkiRsa (seed, secret, key))) pixels image = do
  let encrypted = OAEP.encryptWithSeed (BS.pack seed) oaepParams key $ BS.pack secret
  case encrypted of
       Left MessageTooLong -> addAdditionalPublicPkiState (Just (PublicPkiRsa (seed, tail secret, key))) pixels image
       Left err -> error $ "Unexpected error in OAEP.encryptWithSeed: " ++ (show err)
       Right b -> do
         writeBytes pixels image $ LBS.fromStrict b
         salt <- getRandomByteStringM 256
         addSeedM [BS.bitStringLazy $ hmacSha512Pbkdf2 (LBS.pack secret) salt 5]

addAdditionalPublicPkiState (Just (PublicPkiEcc temporaryKey publicKey)) pixels image = do
  let key = BS.pack $ BA.unpack $ Curve.dh publicKey temporaryKey
      toWrite = LBS.pack $ BA.unpack $ Curve.toPublic temporaryKey
  writeBytes pixels image toWrite
  addSeedM $ createAes256RngState key
--------------------------------------------------------------------------------

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
  replaceSeedM [BS.bitStringLazy $ hmacSha512Pbkdf2 newPbkdfSecret (LBS.concat [bigSalt, salt, extraSalt]) 5]
  aesSecret2 <- getRandomByteStringM 32
  addSeedM $ createAes256RngState $ LBS.toStrict aesSecret1
  addSeedM $ createAes256RngState $ LBS.toStrict aesSecret2



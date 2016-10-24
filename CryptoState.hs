{-# LANGUAGE FlexibleContexts #-}

module CryptoState (createPublicKeyState, readPrivateKey, addAdditionalPrivatePkiState, addAdditionalPublicPkiState, createRandomStates, createSignatureState, createVerifySignatureState, addSignature, verifySignature) where

import AesEngine (createAes256RngState)
import BitStringToRandom (replaceSeedM, addSeedM, getRandomByteStringM)
import ImageFileHandler (readBytes, writeBytes, writeBytes_, getCryptoPrimitives, readSalt, pngDynamicMap)
import Pbkdf2 (hmacSha512Pbkdf2)

import Codec.Picture.Types (imageWidth, imageHeight)
import Control.Exception (Exception, throw)
import Crypto.Error (CryptoFailable(CryptoPassed))
import Crypto.Hash (SHA3_256(..), hashDigestSize)
import Crypto.PubKey.RSA.Types (private_size, Error(MessageTooLong), public_size)
import Crypto.Random.Entropy (getEntropy)
import Data.Maybe (isNothing, isJust, fromJust)
import Data.Typeable (Typeable)
import Data.Word (Word8)

import qualified Crypto.PubKey.Curve25519 as Curve
import qualified Crypto.PubKey.Ed25519 as ED
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import qualified Data.BitString as BiS
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified EccKeys
import qualified PemData (readPublicKey, readPrivateKey)

oaepParams = OAEP.defaultOAEPParams SHA3_256

data CryptoStateException = CouldNotReadPkiFileException |
                            CouldNotAddSignature |
                            CouldNotVerifySignature deriving (Show, Typeable)
instance Exception CryptoStateException

data PrivatePki = PrivatePkiRsa RSA.PrivateKey
                | PrivatePkiEcc EccKeys.SecretEccKey

data PublicPki = PublicPkiRsa ([Word8], [Word8], RSA.PublicKey)
               | PublicPkiEcc EccKeys.SecretEccKey EccKeys.PublicEccKey

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
  addSeedM [(BiS.bitStringLazy $ hmacSha512Pbkdf2 (C8.fromStrict decrypted) salt 5)]

addAdditionalPrivatePkiState (Just (PrivatePkiEcc key)) pixels image = do
  encryptedKey <- readBytes pixels image $ 32 -- ECC key size
  let CryptoPassed pubKey = Curve.publicKey $ LBS.toStrict encryptedKey
      key' = BS.pack $ BA.unpack $ Curve.dh pubKey $ EccKeys.getSecretCryptoKey key
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
         addSeedM [BiS.bitStringLazy $ hmacSha512Pbkdf2 (LBS.pack secret) salt 5]

addAdditionalPublicPkiState (Just (PublicPkiEcc temporaryKey publicKey)) pixels image = do
  let temporaryKey' = EccKeys.getSecretCryptoKey temporaryKey
      key = BS.pack $ BA.unpack $ Curve.dh (EccKeys.getPublicCryptoKey publicKey) $ temporaryKey'
      toWrite = LBS.pack $ BA.unpack $ Curve.toPublic temporaryKey'
  writeBytes pixels image toWrite
  addSeedM $ createAes256RngState key
--------------------------------------------------------------------------------

createSignatureState filename = do
  key <- readPrivateKey filename
  case key of
       Nothing -> return Nothing
       k@(Just (PrivatePkiEcc _)) -> return k
       _ -> throw CouldNotReadPkiFileException

addSignature Nothing _ _ _ = return ()
addSignature (Just (PrivatePkiEcc key)) msg pixels image = do
  let key' = EccKeys.getSecretSignKey key
  case key' of
       Nothing -> throw CouldNotAddSignature 
       Just k -> do
         hashPosition <- getCryptoPrimitives pixels 512 -- Signature size
         signatureSalt <- getRandomByteStringM 64
         let toSign = BS.pack $ (LBS.unpack signatureSalt) ++  msg
             signature = ED.sign k (ED.toPublic k) toSign
         writeBytes_ hashPosition image (LBS.pack $ BA.unpack signature)

createVerifySignatureState filename = do
  key <- createPublicKeyState filename
  case key of
       Nothing -> return Nothing
       k@(Just (PublicPkiEcc _ _)) -> return $ k
       _ -> throw CouldNotReadPkiFileException

verifySignature Nothing _ _ _ = return Nothing
verifySignature (Just (PublicPkiEcc _ key)) msg pixels image = do
  signature <- readBytes pixels image $ 64 -- ED25519 signature size
  signatureSalt <- getRandomByteStringM 64
  let key' = EccKeys.getPublicSignKey key
  let signature' = ED.signature $ BS.pack $ LBS.unpack signature
  case (key', signature') of
       (Just k, CryptoPassed s) -> do
         let toSign = BS.append (LBS.toStrict signatureSalt) msg
         return $ Just $ ED.verify k toSign s
       _ -> throw CouldNotVerifySignature
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
  replaceSeedM [BiS.bitStringLazy $ hmacSha512Pbkdf2 newPbkdfSecret (LBS.concat [bigSalt, salt, extraSalt]) 5]
  aesSecret2 <- getRandomByteStringM 32
  addSeedM $ createAes256RngState $ LBS.toStrict aesSecret1
  addSeedM $ createAes256RngState $ LBS.toStrict aesSecret2

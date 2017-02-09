{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE Trustworthy #-}

module CryptoState (createPublicKeyState, readPrivateKey, addAdditionalPrivatePkiState, addAdditionalPublicPkiState, createRandomStates, createSignatureState, createVerifySignatureState, addSignature, verifySignature) where

import SteganographyContainer (readBytes, writeBytes, writeBytesP, getPrimitives, readSalt, bitsAvailable, WritableSteganographyContainer(..))
import safe AesEngine (createAes256RngState)
import safe Pbkdf2 (hmacSha512Pbkdf2)

import Codec.Picture.Types (imageWidth, imageHeight)
import Crypto.Hash (SHA3_256(..), hashDigestSize)
import Crypto.PubKey.RSA.Types (private_size, Error(MessageTooLong), public_size)
import Crypto.Random.Entropy (getEntropy)
import safe Control.Exception (Exception, throw)
import safe Crypto.Error (CryptoFailable(CryptoPassed))
import safe Crypto.RandomMonad (replaceSeedM, addSeedM, getRandomByteStringM, RndST)
import safe Data.Maybe (isNothing, isJust, fromJust)
import safe Data.Typeable (Typeable)
import safe Data.Word (Word8)

import qualified Crypto.PubKey.Curve25519 as Curve
import qualified Crypto.PubKey.Ed25519 as ED
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import qualified Data.BitString as BiS
import qualified Data.ByteArray as BA
import qualified EccKeys
import qualified PemData (readPublicKey, readPrivateKey)
import safe qualified Data.ByteString as BS
import safe qualified Data.ByteString.Lazy as LBS
import safe qualified Data.ByteString.Lazy.Char8 as C8

oaepParams = OAEP.defaultOAEPParams SHA3_256

data CryptoStateException = CouldNotReadPkiFileException |
                            CouldNotAddSignature |
                            CouldNotVerifySignature deriving (Show, Typeable)
instance Exception CryptoStateException

data PrivatePki = PrivatePkiRsa RSA.PrivateKey
                | PrivatePkiEcc EccKeys.SecretEccKey

data PublicPki = PublicPkiRsa ([Word8], [Word8], RSA.PublicKey)
               | PublicPkiEcc EccKeys.SecretEccKey EccKeys.PublicEccKey

readPrivateKey fileData
  | fileData == BS.empty = Nothing
  | otherwise = do
    let rsaKey = PemData.readPrivateKey $ LBS.fromStrict fileData
    let eccKey = EccKeys.decodeSecretKey fileData
    if isJust rsaKey
       then Just $ PrivatePkiRsa $ fromJust rsaKey
       else if isJust eccKey
               then Just $ PrivatePkiEcc $ fromJust eccKey
               else throw CouldNotReadPkiFileException

createPublicRsaKeyState fileData = do
  privateKey <- PemData.readPublicKey fileData
  if isNothing privateKey
     then return Nothing
     else do
       let Just a = privateKey
       seed <- getEntropy $ hashDigestSize $ OAEP.oaepHash oaepParams
       secret <- getEntropy $ public_size a
       return $ Just (BS.unpack seed, BS.unpack secret, a)

createPublicEccKeyState fileData = do
  let eccKey = EccKeys.decodePublicKey fileData
  if isNothing eccKey
     then return $ Nothing
     else do
       secret <- EccKeys.generateSecretKey
       return $ Just $ PublicPkiEcc secret (fromJust eccKey)

createPublicKeyState fileData
  | fileData == C8.empty = return Nothing
  | otherwise = do
    rsaState <- createPublicRsaKeyState fileData
    eccKey <- createPublicEccKeyState $ LBS.toStrict fileData
    if isJust rsaState
       then return $ Just $ PublicPkiRsa $ fromJust rsaState
       else if isJust eccKey
               then return $ eccKey
               else throw CouldNotReadPkiFileException

--------------------------------------------------------------------------------
addAdditionalPrivatePkiState Nothing _ = return ()

addAdditionalPrivatePkiState (Just (PrivatePkiRsa key)) reader = do
  encrypted <- readBytes reader $ fromIntegral $ private_size key
  let Right decrypted = OAEP.decrypt Nothing oaepParams key (LBS.toStrict encrypted)
  salt <- getRandomByteStringM 256
  addSeedM [(BiS.bitStringLazy $ hmacSha512Pbkdf2 (C8.fromStrict decrypted) salt 5)]

addAdditionalPrivatePkiState (Just (PrivatePkiEcc key)) reader = do
  encryptedKey <- readBytes reader $ 32 -- ECC key size
  let CryptoPassed pubKey = Curve.publicKey $ LBS.toStrict encryptedKey
      key' = BS.pack $ BA.unpack $ Curve.dh pubKey $ EccKeys.getSecretCryptoKey key
  addSeedM $ createAes256RngState $ key'
--------------------------------------------------------------------------------
addAdditionalPublicPkiState Nothing _ = return $ Right ()

addAdditionalPublicPkiState (Just (PublicPkiRsa (seed, secret, key))) writer = do
  let encrypted = OAEP.encryptWithSeed (BS.pack seed) oaepParams key $ BS.pack secret
  case encrypted of
       Left MessageTooLong -> addAdditionalPublicPkiState (Just (PublicPkiRsa (seed, tail secret, key))) writer
       Left err -> return $ Left $ "Unexpected error in OAEP.encryptWithSeed: " ++ (show err)
       Right b -> do
         result <- writeBytes writer $ LBS.fromStrict b
         case result of
           Left err -> return $ Left err
           Right _ -> do
             salt <- getRandomByteStringM 256
             addSeedM [BiS.bitStringLazy $ hmacSha512Pbkdf2 (LBS.pack secret) salt 5]
             return $ Right ()

addAdditionalPublicPkiState (Just (PublicPkiEcc temporaryKey publicKey)) writer = do
  let temporaryKey' = EccKeys.getSecretCryptoKey temporaryKey
      key = BS.pack $ BA.unpack $ Curve.dh (EccKeys.getPublicCryptoKey publicKey) $ temporaryKey'
      toWrite = LBS.pack $ BA.unpack $ Curve.toPublic temporaryKey'
  result <- writeBytes writer toWrite
  case result of
    Left msg -> return $ Left msg
    Right () -> do
      addSeedM $ createAes256RngState key
      return $ Right ()
--------------------------------------------------------------------------------

createSignatureState filename = do
  let key =readPrivateKey filename
  case key of
       Nothing -> Nothing
       k@(Just (PrivatePkiEcc _)) -> k
       _ -> throw CouldNotReadPkiFileException

addSignature :: WritableSteganographyContainer a p => Maybe PrivatePki -> [Word8] -> a s -> RndST s (Either String ())
addSignature Nothing _ _ = return $ Right ()
addSignature (Just (PrivatePkiEcc key)) msg writer = do
  let key' = EccKeys.getSecretSignKey key
  case key' of
       Nothing -> return $ Left $ "Signature key not valid"
       Just k -> do
         hashPosition <- getPrimitives writer 512 -- Signature size
         signatureSalt <- getRandomByteStringM 64
         let toSign = BS.pack $ (LBS.unpack signatureSalt) ++  msg
             signature = ED.sign k (ED.toPublic k) toSign
         result <- writeBytesP writer hashPosition (LBS.pack $ BA.unpack signature)
         case result of
              Right () -> return $ Right ()
              Left msg -> return $ Left $ "Could not add signature: " ++ msg

createVerifySignatureState filename = do
  key <- createPublicKeyState filename
  case key of
       Nothing -> return Nothing
       k@(Just (PublicPkiEcc _ _)) -> return $ k
       _ -> throw CouldNotReadPkiFileException

verifySignature Nothing _ _ = return Nothing
verifySignature (Just (PublicPkiEcc _ key)) msg reader = do
  signature <- readBytes reader $ 64 -- ED25519 signature size
  signatureSalt <- getRandomByteStringM 64
  let key' = EccKeys.getPublicSignKey key
  let signature' = ED.signature $ BS.pack $ LBS.unpack signature
  case (key', signature') of
       (Just k, CryptoPassed s) -> do
         let toSign = BS.append (LBS.toStrict signatureSalt) msg
         return $ Just $ ED.verify k toSign s
       _ -> throw CouldNotVerifySignature
--------------------------------------------------------------------------------
createRandomStates reader salt minimumEntropyBytes = do
  saltLength' <- bitsAvailable reader
  let saltLength = quot saltLength' 30
  bigSalt <- readSalt reader $ saltLength
  extraSalt <- getRandomByteStringM $ max 0 $ minimumEntropyBytes - (fromIntegral $ quot saltLength 8)
  newPbkdfSecret <- getRandomByteStringM 256
  aesSecret1 <- getRandomByteStringM 32
  replaceSeedM [BiS.bitStringLazy $ hmacSha512Pbkdf2 newPbkdfSecret (LBS.concat [bigSalt, salt, extraSalt]) 5]
  aesSecret2 <- getRandomByteStringM 32
  addSeedM $ createAes256RngState $ LBS.toStrict aesSecret1
  addSeedM $ createAes256RngState $ LBS.toStrict aesSecret2

{-# LANGUAGE OverloadedStrings #-}
module EccKeys (generateKeyPair, readPublicKey, readSecretKey, SecretKeyPath(..), PublicKeyPath(..), generateSecretKey, PublicEccKey(), SecretEccKey(), getSecretCryptoKey, getSecretSignKey, getPublicCryptoKey, getPublicSignKey) where

import Control.Exception (Exception, throw)
import Crypto.Random.Entropy (getEntropy)
import Crypto.Error (CryptoFailable(CryptoPassed, CryptoFailed))
import Data.Either (isRight)
import Data.Typeable (Typeable)

import qualified Crypto.PubKey.Curve25519 as EC
import qualified Crypto.PubKey.Ed25519 as ED
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as C8

data SecretKeyPath = SecretKeyPath FilePath
data PublicKeyPath = PublicKeyPath FilePath

data PublicEccKey = PublicEccKey EC.PublicKey |
                    PublicEccKeyWithEd EC.PublicKey ED.PublicKey

data SecretEccKey = SecretEccKey EC.SecretKey |
                    SecretEccKeyWithEd EC.SecretKey ED.SecretKey

getSecretCryptoKey (SecretEccKey key) = key
getSecretCryptoKey (SecretEccKeyWithEd key _) = key

getSecretSignKey (SecretEccKey _) = Nothing
getSecretSignKey (SecretEccKeyWithEd _ key) = Just key

getPublicCryptoKey (PublicEccKey key) = key
getPublicCryptoKey (PublicEccKeyWithEd key _) = key

getPublicSignKey (PublicEccKey _) = Nothing
getPublicSignKey (PublicEccKeyWithEd _ key) = Just key

publicKeyMagic = C8.pack "SteganographyPublicKey_v1: "
secretKeyMagic = C8.pack "DO NOT EVER SHARE THIS FILE WITH ANYONE!\n\nSteganographySecretKey_v1: "

encodeWithMagic magic d = BS.append magic $ C8.unwords $ map (\x -> B64.encode $ BS.pack x) d

decodeWithMagic magic d = let (corr, d') = BS.splitAt (BS.length magic) d
                              words' = words $ C8.unpack d'
                              b64 toDecode = let decoded = B64.decode toDecode
                                               in if isRight decoded
                                                     then let Right r = decoded in r
                                                     else BS.empty
                            in if corr == magic
                                  then map (\var -> b64 $ C8.pack var) words'
                                  else []

encodePublicKey :: PublicEccKey -> BS.ByteString
encodePublicKey (PublicEccKey cryptoKey) = encodeWithMagic publicKeyMagic [BA.unpack cryptoKey]
encodePublicKey (PublicEccKeyWithEd cryptoKey signKey) = encodeWithMagic publicKeyMagic [BA.unpack cryptoKey, BA.unpack signKey]

decodePublicKey :: BS.ByteString -> Maybe PublicEccKey
decodePublicKey input = let decoded = decodeWithMagic publicKeyMagic input
                          in case decoded of
                                  [cryptoKey] -> let key = EC.publicKey cryptoKey
                                                   in case key of
                                                           CryptoPassed cryptoKey' -> Just $ PublicEccKey cryptoKey'
                                                           CryptoFailed _ -> Nothing
                                  [cryptoKey, signKey] -> let keys = (EC.publicKey cryptoKey, ED.publicKey signKey)
                                                            in case keys of
                                                                    (CryptoPassed cryptoKey', CryptoPassed signKey') -> Just $ PublicEccKeyWithEd cryptoKey' signKey'
                                                                    _ -> Nothing
                                  _ -> Nothing

encodeSecretKey :: SecretEccKey -> BS.ByteString
encodeSecretKey (SecretEccKey cryptoKey) = encodeWithMagic secretKeyMagic [BA.unpack cryptoKey]
encodeSecretKey (SecretEccKeyWithEd cryptoKey signKey) = encodeWithMagic secretKeyMagic [BA.unpack cryptoKey, BA.unpack signKey]

decodeSecretKey :: BS.ByteString -> Maybe SecretEccKey
decodeSecretKey input = let decoded = decodeWithMagic secretKeyMagic input
                          in case decoded of
                                  [cryptoKey] -> let key = EC.secretKey cryptoKey
                                                   in case key of
                                                           CryptoPassed cryptoKey' -> Just $ SecretEccKey cryptoKey'
                                                           CryptoFailed _ -> Nothing
                                  [cryptoKey, signKey] -> let keys = (EC.secretKey cryptoKey, ED.secretKey signKey)
                                                            in case keys of
                                                                    (CryptoPassed cryptoKey', CryptoPassed signKey') -> Just $ SecretEccKeyWithEd cryptoKey' signKey'
                                                                    _ -> Nothing
                                  _ -> Nothing

readPublicKey :: PublicKeyPath -> IO (Maybe PublicEccKey)
readPublicKey (PublicKeyPath pubKey) = do
  keyData <- C8.readFile pubKey
  return $ decodePublicKey keyData

readSecretKey :: SecretKeyPath -> IO (Maybe SecretEccKey)
readSecretKey (SecretKeyPath secKey) = do
  keyData <- C8.readFile secKey
  return $ decodeSecretKey keyData

data CryptoGenerationException = CryptoGenerationException deriving (Show, Typeable)
instance Exception CryptoGenerationException

generateSecretKey = do
  entropy <- getEntropy 32 :: IO BS.ByteString
  entropy2 <- getEntropy 32 :: IO BS.ByteString
  let eccKey = EC.secretKey entropy
      edKey = ED.secretKey entropy2
  case (eccKey, edKey) of
       (CryptoPassed cryptoKey, CryptoPassed signKey) -> return $ SecretEccKeyWithEd cryptoKey signKey
       _ -> throw CryptoGenerationException

toPublic (SecretEccKeyWithEd cryptoKey signKey) = PublicEccKeyWithEd (EC.toPublic cryptoKey) $ ED.toPublic signKey

generateKeyPair (SecretKeyPath privKey, PublicKeyPath pubKey) = do
  secretKey <- generateSecretKey
  let publicKey = toPublic secretKey
  C8.writeFile pubKey $ encodePublicKey publicKey
  C8.writeFile privKey $ encodeSecretKey secretKey


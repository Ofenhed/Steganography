{-# LANGUAGE OverloadedStrings #-}
module EccKeys (generatePrivateEccKey) where

import Crypto.Random.Entropy (getEntropy)
import Crypto.Error (CryptoFailable(CryptoPassed, CryptoFailed))
import Crypto.PubKey.Curve25519 (secretKey, publicKey, toPublic, dh, PublicKey(..), SecretKey(..))
import Data.Char (chr)
import Data.Either (isRight)

import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as C8

publicKeyMagic = C8.pack "SteganographyPublicKey_v1: "
secretKeyMagic = C8.pack "DO NOT EVER SHARE THIS FILE WITH ANYONE!\n\nSteganographySecretKey_v1: "

encodeWithMagic magic d = BS.append magic $ B64.encode $ BS.pack  $ BA.unpack d

decodeWithMagic magic dFunc d = let (corr, d') = BS.splitAt (BS.length magic) d
                                    b64 = B64.decode d'
                                    Right b64' = b64
                                    decoded = if isRight b64
                                                 then dFunc $ b64'
                                                 else dFunc BS.empty
                                  in if corr == magic && isRight b64
                                        then case decoded of
                                                  CryptoPassed key -> Just key
                                                  CryptoFailed _ -> Nothing
                                        else Nothing

encodePublicKey :: PublicKey -> BS.ByteString
encodePublicKey = encodeWithMagic publicKeyMagic

decodePublicKey :: BS.ByteString -> Maybe PublicKey
decodePublicKey = decodeWithMagic publicKeyMagic publicKey

encodeSecretKey :: SecretKey -> BS.ByteString
encodeSecretKey = encodeWithMagic secretKeyMagic

decodeSecretKey :: BS.ByteString -> Maybe SecretKey
decodeSecretKey = decodeWithMagic secretKeyMagic secretKey

readPublicKey :: FilePath -> IO (Maybe PublicKey)
readPublicKey pubKey = do
  keyData <- C8.readFile pubKey
  return $ decodePublicKey keyData

readSecretKey :: FilePath -> IO (Maybe SecretKey)
readSecretKey secKey = do
  keyData <- C8.readFile secKey
  return $ decodeSecretKey keyData

generatePrivateEccKey :: (FilePath, FilePath) -> IO Bool
generatePrivateEccKey (privKey, pubKey) = do
  entropy <- getEntropy 32 :: IO BS.ByteString
  let key = secretKey entropy
  case key of
       CryptoFailed _ -> return False
       CryptoPassed secret -> do
         let public = toPublic secret
         C8.writeFile pubKey $ encodePublicKey public
         C8.writeFile privKey $ encodeSecretKey secret
         return True


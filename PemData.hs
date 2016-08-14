module PemData (readPublicKey, readPrivateKey) where

import Data.X509.File (readKeyFile)
import Data.X509 (PrivKey(PrivKeyRSA))
import Data.X509 (PubKey(PubKeyRSA))
import Data.PEM (pemParseLBS, pemContent, pemName, PEM)
import qualified Data.ByteString.Lazy.Char8 as C8
import Data.ASN1.Encoding (decodeASN1')
import Data.ASN1.Types (ASN1)
import Data.ASN1.BinaryEncoding (BER(..))
import Data.ASN1.Types (fromASN1)


readPrivateKey file = do
  keys <- readKeyFile file
  if length keys /= 1
     then return Nothing
     else let PrivKeyRSA privateKey = keys !! 0 in return $ Just $ privateKey

readPublicKey [] = return Nothing
readPublicKey file = do
  keyData <- C8.readFile file
  let decodeASN1'' a b = case decodeASN1' a b of
                            Left _ -> Left "Could not parse PEM file"
                            (Right y) -> Right y
      key = do
            [decodedKeyData] <- pemParseLBS $ keyData
            d <- decodeASN1'' BER $ pemContent decodedKeyData
            (PubKeyRSA pubKey, _) <- fromASN1 d :: Either String (PubKey, [ASN1])
            return pubKey
  case key of
       Left _ -> return Nothing
       Right a -> return $ Just a

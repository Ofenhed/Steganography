module PemData (readPublicKey, readPrivateKey) where

import Data.ASN1.BinaryEncoding (BER(..))
import Data.ASN1.Encoding (decodeASN1')
import Data.ASN1.Types (ASN1)
import Data.ASN1.Types (fromASN1)
import Data.PEM (pemParseLBS, pemContent)
import Data.X509.File (readKeyFile)
import Data.X509 (PrivKey(PrivKeyRSA), PubKey(PubKeyRSA, PubKeyEC))

import qualified Data.ByteString.Lazy.Char8 as C8

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
            pub <- fromASN1 d :: Either String (PubKey, [ASN1])
            case pub of
                 ((PubKeyRSA a), _) -> return a
                 --(key@(PubKeyEC _), b) -> return key
                 otherwise -> Left []
  case key of
       Left _ -> return Nothing
       Right a -> return $ Just a

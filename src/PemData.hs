module PemData (readPublicKey, readPrivateKey) where

import Data.ASN1.BinaryEncoding (BER(..))
import Data.ASN1.Encoding (decodeASN1')
import Data.ASN1.Types (ASN1)
import Data.ASN1.Types (fromASN1)
import Data.PEM (pemParseLBS, pemContent)
import Data.X509 (PrivKey(PrivKeyRSA), PubKey(PubKeyRSA))

import Data.ASN1.Types
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.Maybe
import qualified Data.X509 as X509
import           Data.X509.Memory (pemToKey)
import Data.PEM (pemParseLBS, pemContent, pemName, PEM)
import qualified Data.ByteString.Lazy as L


import qualified Data.ByteString.Lazy.Char8 as C8

--readPEMs :: FilePath -> IO [PEM]
readPEMs fileData = do
    return $ either error id $ pemParseLBS fileData

-- | return all the public key that were successfully read from a file.
--readKeyFile :: FilePath -> IO [X509.PrivKey]
readKeyFile fileData = catMaybes . foldl pemToKey [] <$> readPEMs fileData

readPrivateKey fileData = do
  keys <- readKeyFile fileData
  if length keys /= 1
     then Nothing
     else let PrivKeyRSA privateKey = keys !! 0 in Just $ privateKey

readPublicKey keyData
 | C8.empty == keyData = return Nothing
 | otherwise = do
    let decodeASN1'' a b = case decodeASN1' a b of
                              Left _ -> Left "Could not parse PEM file"
                              (Right y) -> Right y
        key = do
              decodedKeyData <- pemParseLBS $ keyData
              if length decodedKeyData /= 1 then Left "No pem data found" else Right ()
              let [decodedKeyData'] = decodedKeyData
              d <- decodeASN1'' BER $ pemContent decodedKeyData'
              pub <- fromASN1 d :: Either String (PubKey, [ASN1])
              case pub of
                   ((PubKeyRSA a), _) -> return a
                   --(key@(PubKeyEC _), b) -> return key
                   _ -> Left []
    case key of
         Left _ -> return Nothing
         Right a -> return $ Just a

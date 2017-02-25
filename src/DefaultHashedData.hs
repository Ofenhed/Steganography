{-# LANGUAGE MultiParamTypeClasses #-}
module DefaultHashedData (DefaultHashedData(..)) where

import HashedDataContainer (HashedDataContainer(..))
import SteganographyContainer (WritableSteganographyContainer(..))
import Crypto.RandomMonad (getRandomByteStringM)

import Crypto.Hash (SHA1(..), hashDigestSize, digestFromByteString)
import Crypto.MAC.HMAC (Context, update, initialize, finalize, hmacGetDigest)
import Data.Bits (xor)
import Control.Monad.Trans.Class (lift)

import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as LC8
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString as BS
import qualified Data.ByteArray as BA

import Data.STRef (STRef, newSTRef, modifySTRef, readSTRef)

data DefaultHashedData = DefaultHashedData
data HashHolder s = HashHolder (STRef s (Context SHA1))

instance HashedDataContainer DefaultHashedData HashHolder where
  getHashSize _ = fromIntegral $ hashDigestSize SHA1

  hasherInit a = do
    hashSalt <- getRandomByteStringM $ fromIntegral $ getHashSize a
    ref <- lift $ newSTRef $ initialize (LBS.toStrict hashSalt)
    return $ Right $ HashHolder ref

  hasherUpdate _ (HashHolder hasher) byte = do
    macXorBytes <- getRandomByteStringM 1
    let macXorByte' = LBS.head macXorBytes
    lift $ modifySTRef hasher (\h -> update h $ BS.singleton $ xor (fromIntegral $ fromEnum byte) macXorByte')
    return $ Right ()

  hasherCheck _ (HashHolder hasher) target = do
    hash <- lift $ readSTRef hasher
    let this = hmacGetDigest $ finalize hash
    let target' = digestFromByteString $ LC8.toStrict target
    case target' of
      Nothing -> return $ Left "Problem reading the hash from the file"
      Just target'' -> return $ Right $ target'' == this

  hasherFinalize _ (HashHolder hasher) writer primitives = do
    hash <- lift $ readSTRef hasher
    let this = hmacGetDigest $ finalize hash
        bs = LBS.pack $ BA.unpack this
    writeResult <- writeBytesP writer primitives bs
    case writeResult of
      Left err -> return $ Left err
      Right () -> return $ Right ()


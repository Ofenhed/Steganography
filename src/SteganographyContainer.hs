{-# LANGUAGE MultiParamTypeClasses #-}
module SteganographyContainer (SteganographyContainer) where

import Crypto.RandomMonad (RndT)
import Control.Monad.ST (ST)

import qualified Data.Text as T

import qualified Data.ByteString.Lazy as LBS
import qualified Data.BitString as BiS

class SteganographyContainer a where
  writeBits :: a -> BiS.BitString -> RndT (ST s) Bool
  readBits :: a -> Word -> RndT (ST s) BiS.BitString

  writeBytes :: a -> LBS.ByteString -> RndT (ST s) Bool
  readBytes :: a -> Word -> RndT (ST s) LBS.ByteString
  readSalt :: a -> Word -> RndT (ST s) LBS.ByteString

  storageAvailable :: a -> RndT (ST s) (Maybe Word)
  storageAvailable _ = return Nothing

  writeBytes state bytes = writeBits state $ BiS.bitStringLazy bytes
  readBytes state len = readBits state (len * 8) >>= (return . BiS.realizeBitStringLazy)

class (SteganographyContainer a) => SteganographyContainerWithPrimitives a p where
  getPrimitives :: a -> RndT (ST s) p
  writeBitsP :: a -> p -> BiS.BitString -> RndT (ST s) Bool
  writeBytesP :: a -> p -> BiS.BitString -> RndT (ST s) Bool

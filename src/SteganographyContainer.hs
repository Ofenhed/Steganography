{-# LANGUAGE FunctionalDependencies #-}
module SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..), SteganographyContainerWithPrimitives(..)) where

import Crypto.RandomMonad (RndT)
import Control.Monad.ST (ST)

import qualified Data.Text as T

import qualified Data.ByteString.Lazy as LBS
import qualified Data.BitString as BiS

class (Monad s) => SteganographyContainer s a where
  readBits :: a -> Word -> RndT s BiS.BitString
  readSalt :: a -> Word -> RndT s LBS.ByteString

  readBytes :: a -> Word -> RndT s LBS.ByteString
  length :: a -> RndT s Word

  createContainer :: LBS.ByteString -> s (Either (Maybe [char]) a)

  readBytes state len = readBits state (len * 8) >>= (return . BiS.realizeBitStringLazy)

class (Monad s, SteganographyContainer s c) => WritableSteganographyContainer s c a | a -> c where
  writeBits :: a -> BiS.BitString -> RndT s Bool

  writeBytes :: a -> LBS.ByteString -> RndT s Bool

  withSteganographyContainer :: c -> (a -> s (Either (Maybe [char]) c)) -> s (Either (Maybe [char]) c)
  unsafeWithSteganographyContainer :: c -> (a -> s (Either (Maybe [char]) c)) -> s (Either (Maybe [char]) c)

  storageAvailable :: a -> RndT s (Maybe Word)
  storageAvailable _ = return Nothing

  writeBytes state bytes = writeBits state $ BiS.bitStringLazy bytes
  unsafeWithSteganographyContainer = withSteganographyContainer

class SteganographyContainerWithPrimitives a where
  id :: a -> a
--class (WritableSteganographyContainer s a c) => SteganographyContainerWithPrimitives s c a p where
--  getPrimitives :: a -> RndT s p
--  writeBitsP :: a -> p -> BiS.BitString -> RndT s Bool
--  writeBytesP :: a -> p -> BiS.BitString -> RndT s Bool

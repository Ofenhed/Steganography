{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE RankNTypes #-}
module SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..)) where

import Crypto.RandomMonad (RndST)
import Control.Monad.ST (ST)

import qualified Data.Text as T

import qualified Data.ByteString.Lazy as LBS
import qualified Data.BitString as BiS

byteSize = 8

class SteganographyContainer s a where
  readBits :: a -> Word -> RndST s BiS.BitString
  readSalt :: a -> Word -> RndST s LBS.ByteString
  readBytes :: a -> Word -> RndST s LBS.ByteString

  createContainer :: LBS.ByteString -> ST s (Either String a)
  withSteganographyContainer :: a -> (forall c p. WritableSteganographyContainer s c p => c -> RndST s (Either String a)) -> RndST s (Either String a)
  unsafeWithSteganographyContainer :: a -> (forall c p. WritableSteganographyContainer s c p => c -> RndST s (Either String a)) -> RndST s (Either String a)

  readBytes state len = readBits state (len * 8) >>= (return . BiS.realizeBitStringLazy)
  unsafeWithSteganographyContainer = withSteganographyContainer

class WritableSteganographyContainer s a p | a -> p where
  -- With primitives
  getPrimitives :: a -> Word -> RndST s p
  writeBitsP :: a -> p -> BiS.BitString -> RndST s Bool
  writeBytesP :: a -> p -> LBS.ByteString -> RndST s Bool

  -- Without primitives
  writeBits :: a -> BiS.BitString -> RndST s Bool
  writeBytes :: a -> LBS.ByteString -> RndST s Bool

  storageAvailable :: a -> RndST s (Maybe Word)
  storageAvailable _ = return Nothing

  -- Defaults
  writeBytes state bytes = do
    p <- getPrimitives state (byteSize * (fromIntegral $ LBS.length bytes))
    writeBytesP state p bytes

  writeBits state bits = do
    p <- getPrimitives state $ fromIntegral $ BiS.length bits
    writeBitsP state p bits

  writeBytesP state prim bytes = writeBitsP state prim $ BiS.bitStringLazy bytes

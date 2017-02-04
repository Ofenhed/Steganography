{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE RankNTypes #-}
module SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..)) where

import Control.Monad.ST (ST)
import Crypto.RandomMonad (RndST)

import qualified Data.BitString as BiS
import qualified Data.ByteString.Lazy as LBS

byteSize = 8

class SteganographyContainer s a where
  createContainer :: LBS.ByteString -> ST s (Either String a)
  withSteganographyContainer :: a -> (forall c p. WritableSteganographyContainer s c p => c -> RndST s (Either String ())) -> RndST s (Either String LBS.ByteString)
  unsafeWithSteganographyContainer :: a -> (forall c p. WritableSteganographyContainer s c p => c -> RndST s (Either String ())) -> RndST s (Either String LBS.ByteString)

  -- Readers
  readBits :: a -> Word -> RndST s BiS.BitString
  readSalt :: a -> Word -> RndST s LBS.ByteString
  readBytes :: a -> Word -> RndST s LBS.ByteString
  bytesAvailable :: a -> RndST s Word

  -- Defaults
  readBytes state len = readBits state (len * byteSize) >>= (return . BiS.realizeBitStringLazy)
  unsafeWithSteganographyContainer = withSteganographyContainer

class WritableSteganographyContainer s a p | a -> p where
  -- With primitives
  getPrimitives :: a -> Word -> RndST s p
  writeBitsP :: a -> p -> BiS.BitString -> RndST s (Either String ())
  writeBytesP :: a -> p -> LBS.ByteString -> RndST s (Either String ())

  -- Without primitives
  writeBits :: a -> BiS.BitString -> RndST s (Either String ())
  writeBytes :: a -> LBS.ByteString -> RndST s (Either String ())

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

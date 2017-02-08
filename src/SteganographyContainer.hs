{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE RankNTypes #-}
module SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..), SteganographyContainerOptions(..)) where

import Control.Monad.ST (ST)
import Crypto.RandomMonad (RndST)

import qualified Data.BitString as BiS
import qualified Data.ByteString.Lazy as LBS

byteSize = 8

class (SteganographyContainer b) => SteganographyContainerOptions a b | a -> b where
  createContainer :: a -> LBS.ByteString -> ST s (Either String (b s))

class SteganographyContainer a where
  withSteganographyContainer :: a s -> (forall c p. WritableSteganographyContainer c p => c s -> RndST s (Either String ())) -> RndST s (Either String LBS.ByteString)
  unsafeWithSteganographyContainer :: a s -> (forall c p. WritableSteganographyContainer c p => c s -> RndST s (Either String ())) -> RndST s (Either String LBS.ByteString)

  -- Readers
  readBits :: a s -> Word -> RndST s BiS.BitString
  readSalt :: a s -> Word -> RndST s LBS.ByteString
  readBytes :: a s -> Word -> RndST s LBS.ByteString
  bytesAvailable :: a s -> RndST s Word

  -- Defaults
  readBytes state len = readBits state (len * byteSize) >>= (return . BiS.realizeBitStringLazy)
  unsafeWithSteganographyContainer = withSteganographyContainer

class WritableSteganographyContainer a p | a -> p where
  -- With primitives
  getPrimitives :: a s -> Word -> RndST s p
  writeBitsP :: a s -> p -> BiS.BitString -> RndST s (Either String ())
  writeBytesP :: a s -> p -> LBS.ByteString -> RndST s (Either String ())

  -- Without primitives
  writeBits :: a s -> BiS.BitString -> RndST s (Either String ())
  writeBytes :: a s -> LBS.ByteString -> RndST s (Either String ())

  storageAvailable :: a s -> RndST s (Maybe Word)
  storageAvailable _ = return Nothing

  -- Defaults
  writeBytes state bytes = do
    p <- getPrimitives state (byteSize * (fromIntegral $ LBS.length bytes))
    writeBytesP state p bytes

  writeBits state bits = do
    p <- getPrimitives state $ fromIntegral $ BiS.length bits
    writeBitsP state p bits

  writeBytesP state prim bytes = writeBitsP state prim $ BiS.bitStringLazy bytes

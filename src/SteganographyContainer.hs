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
  -- | Create a 'WritableSteganographyContainer' based on the current
  -- 'SteganographyContainer'.
  withSteganographyContainer :: a s -> (forall c p. WritableSteganographyContainer c p => c s -> RndST s (Either String ())) -> RndST s (Either String LBS.ByteString)
  -- | Create a 'WritableSteganographyContainer' based on the current
  -- 'SteganographyContainer'. This 'SteganographyContainer' must not be used
  -- after this function is called.
  unsafeWithSteganographyContainer :: a s -> (forall c p. WritableSteganographyContainer c p => c s -> RndST s (Either String ())) -> RndST s (Either String LBS.ByteString)

  readBits :: a s -> Word -> RndST s BiS.BitString
  readBytes :: a s -> Word -> RndST s LBS.ByteString
  -- | Read data from the 'SteganographyContainer' as salt from the container.
  -- This function is allowed to return more data than 'len', but not use any
  -- more of the effective storage than 'len'.
  readSalt :: a s -> Word -> RndST s LBS.ByteString

  -- Info about the container
  bytesAvailable :: a s -> RndST s Word
  bitsAvailable :: a s -> RndST s Word

  -- Defaults
  readBytes state len = readBits state (len * byteSize) >>= return . BiS.realizeBitStringLazy
  unsafeWithSteganographyContainer = withSteganographyContainer
  bytesAvailable state = bitsAvailable state >>= return . (*byteSize)
  readSalt state len = readBits state len >>= (return . BiS.realizeBitStringLazy)

class WritableSteganographyContainer a p | a -> p where
  -- | Get primitives which can be used to write on the current position of the
  -- writer stream later.
  getPrimitives :: a s -> Word -> RndST s p
  getPrimitivesBytes :: a s -> Word -> RndST s p
  writeBitsP :: a s -> p -> BiS.BitString -> RndST s (Either String ())
  writeBytesP :: a s -> p -> LBS.ByteString -> RndST s (Either String ())

  -- Without primitives
  writeBits :: a s -> BiS.BitString -> RndST s (Either String ())
  writeBytes :: a s -> LBS.ByteString -> RndST s (Either String ())

  -- | Get number of bits available of storage. This may not be available for some formats, in which case 'Nothing' will be returned. This function will never return a bigger value than 'bitsAvailable'
  storageAvailableBits :: a s -> RndST s (Maybe Word)
  storageAvailableBytes :: a s -> RndST s (Maybe Word)

  -- Defaults
  storageAvailableBits _ = return Nothing
  storageAvailableBytes state = storageAvailableBits state >>= \bits -> case bits of
                                                                             Nothing -> return $ Nothing
                                                                             Just size -> return $ Just $ size * byteSize

  writeBytes state bytes = do
    p <- getPrimitives state (byteSize * (fromIntegral $ LBS.length bytes))
    writeBytesP state p bytes

  writeBits state bits = do
    p <- getPrimitives state $ fromIntegral $ BiS.length bits
    writeBitsP state p bits

  writeBytesP state prim bytes = writeBitsP state prim $ BiS.bitStringLazy bytes

  getPrimitivesBytes state bytes = getPrimitives state (bytes * byteSize)

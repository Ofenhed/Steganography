{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FunctionalDependencies #-}
module HashedDataContainer (HashedDataContainer(..)) where

import Crypto.RandomMonad (RndST(..))
import CryptoContainer (EncryptionContainer(..), DecryptionContainer(..))
import SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..))

import Control.Monad.ST (ST(..))

import qualified Data.ByteString.Lazy as LBS

class HashedDataContainer a hasher | a -> hasher where
  getHashSize :: a -> Word
  hasherInit :: a -> RndST s (Either String (hasher s))
  hasherUpdate :: a -> hasher s -> Char -> RndST s (Either String ())
  hasherCheck :: a -> hasher s -> LBS.ByteString -> RndST s (Either String Bool)
  hasherFinalize :: WritableSteganographyContainer b p => a -> hasher s -> b s -> p -> RndST s (Either String ())

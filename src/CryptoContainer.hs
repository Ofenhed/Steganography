{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FunctionalDependencies #-}
module CryptoContainer (CryptoContainer(..), EncryptionContainer(..), DecryptionContainer(..)) where

import Crypto.RandomMonad (RndST(..))
import SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..))

import Control.Monad.ST (ST(..))

import qualified Data.ByteString.Lazy as LBS

class CryptoContainer a where
  runCrypto :: a -> RndST s (Either String b) -> ST s (Either String b)
  initSymmetricCrypto :: (SteganographyContainer b) => a -> b s -> RndST s (Either String ())

  -- Defaults

  initSymmetricCrypto _ _ = return $ Right ()

class CryptoContainer a => EncryptionContainer a sign | a -> sign where
  initAsymmetricEncrypter :: WritableSteganographyContainer b p => a -> b s -> RndST s (Either String ())

  signerInit :: a -> RndST s (Either String (Maybe (sign s)))
  signerAdd :: a -> Maybe (sign s) -> LBS.ByteString -> RndST s (Either String ())
  signerFinalize :: WritableSteganographyContainer b p => a -> Maybe (sign s) -> b s -> RndST s (Either String ())

  -- Defaults

  initAsymmetricEncrypter _ _ = return $ Right ()

  signerInit _ = return $ Right Nothing
  signerAdd _ Nothing _ = return $ Right ()
  signerFinalize _ Nothing _ = return $ Right ()

class CryptoContainer a => DecryptionContainer a sign | a -> sign where
  initAsymmetricDecrypter :: (SteganographyContainer b) => a -> b s -> RndST s (Either String ())

  verifierInit :: a -> RndST s (Either String (Maybe (sign s)))
  verifierAdd :: a -> Maybe (sign s) -> LBS.ByteString -> RndST s (Either String ())
  verifierFinalize :: SteganographyContainer b => a -> Maybe (sign s) -> b s -> RndST s (Either String (Maybe Bool))

  -- Defaults

  initAsymmetricDecrypter _ _ = return $ Right ()

  verifierInit _ = return $ Right Nothing
  verifierAdd _ Nothing _ = return $ Right ()
  verifierFinalize _ Nothing _ = return $ Right Nothing

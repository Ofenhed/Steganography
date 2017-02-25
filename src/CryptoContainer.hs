{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FunctionalDependencies #-}
module CryptoContainer (CryptoContainer, EncryptionContainer, DecryptionContainer) where

import Crypto.RandomMonad (RndST(..))

import qualified Data.ByteString.Lazy as LBS

class CryptoContainer a where
  runCrypto :: a -> RndST s (Either String LBS.ByteString) -> Either String LBS.ByteString
  initSymmetricCrypto :: a -> RndST s (Either String ())

  -- Defaults

  initSymmetricCrypto _ = return $ Right ()

class CryptoContainer a => EncryptionContainer a sign vsign | a -> sign vsign where
  initAsymmetricEncrypter :: a -> RndST s (Either String ())

  signerInit :: a -> RndST s (Either String (Maybe (sign s)))
  signerAdd :: a -> Maybe (sign s) -> LBS.ByteString -> RndST s (Either String ())
  signerFinalize :: a -> Maybe (sign s) -> RndST s (Either String ())

  -- Defaults

  initAsymmetricEncrypter _ = return $ Right ()

  signerInit _ = return $ Right Nothing
  signerAdd _ Nothing _ = return $ Right ()
  signerFinalize _ Nothing = return $ Right ()

class CryptoContainer a => DecryptionContainer a sign vsign | a -> sign vsign where
  initAsymmetricDecrypter :: a -> RndST s (Either String ())

  verifierInit :: a -> RndST s (Either String (Maybe (vsign s)))
  verifierAdd :: a -> Maybe (vsign s) -> LBS.ByteString -> RndST s (Either String ())
  verifierFinalize :: a -> Maybe (vsign s) -> RndST s (Either String ())

  -- Defaults

  initAsymmetricDecrypter _ = return $ Right ()

  verifierInit _ = return $ Right Nothing
  verifierAdd _ Nothing _ = return $ Right ()
  verifierFinalize _ Nothing = return $ Right ()

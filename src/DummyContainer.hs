{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE RankNTypes #-}
module DummyContainer (DummyContainer(..)) where

import SteganographyContainer (SteganographyContainer(..), WritableSteganographyContainer(..), SteganographyContainerOptions(..))
import Data.Word (Word8)
import Control.Monad.ST (ST)
import Data.STRef (STRef, newSTRef, readSTRef, modifySTRef, writeSTRef)
import Control.Monad.Trans.Class (lift)

import qualified Data.BitString as BiS
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy.Char8 as LBS

data WritableDummy s = WritableDummy (STRef s String) (STRef s Word)

addString :: forall a b s. (Show a, Show b) =>  (STRef s String) -> String -> a -> b -> ST s ()
addString str command arguments response = modifySTRef str $ \before -> before ++ "\n" ++ command ++ " " ++ show arguments ++ " -> " ++ (show $ response)

instance WritableSteganographyContainer WritableDummy [Word] where
  getPrimitives (WritableDummy str cnt) i = do
    num <- lift $ readSTRef cnt
    let newNum = num + i
    let response = [num..newNum-1]
    lift $ writeSTRef cnt newNum
    lift $ addString str "getPrimitives" i $ Just response
    return $ response
  writeBits (WritableDummy str _) bits = do
    lift $ addString str "writeBits" bits ()
    return $ Right ()
  writeBytes (WritableDummy str _) bytes = do
    lift $ addString str "writeBytes" bytes ()
    return $ Right ()
  writeBitsP (WritableDummy str _) primitives bits = do
    lift $ addString str "writeBitsP" (primitives,bits) ()
    return $ Right ()
  writeBytesP (WritableDummy str _) primitives bytes = do
    lift $ addString str "writeByteP" (primitives,bytes) ()
    return $ Right ()

data Dummy s = Dummy (STRef s String)
data DummyContainer = DummyContainer

instance SteganographyContainerOptions DummyContainer Dummy where
  createContainer options _ = newSTRef [] >>= return . Right . Dummy

instance SteganographyContainer Dummy where
  readBits (Dummy str) count = do
    let response = BS.pack $ replicate (fromIntegral count * 8) 0
    lift $ addString str "readBytes" count response
    return $ BiS.bitString $ response

  readBytes (Dummy str) count = do
    let response = LBS.pack $ replicate (fromIntegral count) '0'
    lift $ addString str "readBits" count response
    return $ response

  readSalt (Dummy str) count = do
    let response = LBS.pack $ replicate (fromIntegral count) '0'
    lift $ addString str "readSalt" count response
    return $ response

  bitsAvailable _ = return 9001

  withSteganographyContainer (Dummy stRef) func = do
    counter <- lift $ newSTRef 0
    func (WritableDummy stRef counter)
    actions <- lift $ readSTRef stRef
    return $ Right $ LBS.pack actions


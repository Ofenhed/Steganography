{-# LANGUAGE FlexibleContexts #-}
module ImageFileHandler (readBits, readBytes, writeBits, writeBytes, writeBytes_, readBits_, writeBits_, getCryptoPrimitives, readSalt, readSalt_) where

import BitStringToRandom (getRandomElement, RndST, getRandomM)
import PixelStream (Pixel)

import Codec.Picture.Types
import Control.Monad
import Control.Monad.Trans.Class
import Data.Bits
import qualified Data.BitString as BS
import qualified Data.ByteString.Lazy as ByS

data CryptoPrimitive = CryptoPrimitive (PixelStream.Pixel) (Bool) deriving (Show)
type CryptoStream = [CryptoPrimitive]

getCryptoPrimitives pixels count = do
  read <- forM [1..count] $ \_ -> do
    pixel <- getRandomElement pixels
    inv <- getRandomBoolM
    return $ CryptoPrimitive pixel inv
  return $ read

getRandomBoolM :: RndST s Bool
getRandomBoolM = do
  b <- getRandomM 1
  return $ case b of 1 -> True
                     0 -> False

readBits_ primitives image = do
  read <- forM primitives $ \p -> do
    let CryptoPrimitive (x, y, c) inv = p
    let x' = fromInteger $ toInteger x
    let y' = fromInteger $ toInteger y
    let (PixelRGBA8 red green blue alpha) = pixelAt image x' y'
    let p = case c of 0 -> red .&. 1
                      1 -> green .&. 1
                      2 -> blue .&. 1
    return $ xor inv $ case p of 1 -> True
                                 0 -> False
  return $ BS.fromList read

readSalt_ primitives image = do
  read <- forM primitives $ \p -> do
    let CryptoPrimitive (x, y, c) inv = p
    let x' = fromInteger $ toInteger x
    let y' = fromInteger $ toInteger y
    let (PixelRGBA8 red green blue alpha) = pixelAt image x' y'
    let p = case c of 0 -> red
                      1 -> green
                      2 -> blue
    return $ if inv
                then complement p
                else p
  return $ ByS.pack read

writeBits_ primitives image bits = forM_ (zipWith (\p b -> (p, b)) primitives (BS.toList bits)) $ \(p, bit) -> do
    let CryptoPrimitive (x, y, c) inv = p
    let x' = fromInteger $ toInteger x
    let y' = fromInteger $ toInteger y
    (PixelRGBA8 red green blue alpha) <- readPixel image x' y'
    let newBit = case xor inv bit of True -> 1
                                     False -> 0
    let red' = if c == 0 then (red .&. (complement 1)) .|. newBit
                         else red
    let green' = if c == 1 then (green .&. (complement 1)) .|. newBit
                           else green
    let blue' = if c == 2 then (blue .&. (complement 1)) .|. newBit
                          else blue
    writePixel image x' y' $ PixelRGBA8 red' green' blue' alpha

writeBytes_ primitives image bytes = lift $ writeBits_ primitives image $ BS.bitStringLazy bytes

readBits pixels image count = do
  primitives <- getCryptoPrimitives pixels count
  readBits_ primitives image

readBytes pixels image count = do
  a <- readBits pixels image $ count * 8
  return $ BS.realizeBitStringLazy a

readSalt pixels image count = do
  primitives <- getCryptoPrimitives pixels count
  readSalt_ primitives image

writeBits pixels image bits = do
  primitives <- getCryptoPrimitives pixels $ BS.length bits
  lift $ writeBits_ primitives image bits

writeBytes pixels image bytes = writeBits pixels image $ BS.bitStringLazy bytes

module ImageFileHandler (readBits, readBytes, writeBits, writeBytes) where

import BitStringToRandom (getRandomElement, RndST, getRandomM)

import Codec.Picture.Types
import Control.Monad
import Control.Monad.Trans.Class
import Data.Bits
import qualified Data.BitString as BS

getRandomBoolM :: RndST s Bool
getRandomBoolM = do
  b <- getRandomM 1
  return $ case b of 1 -> True
                     0 -> False

readBits pixels image bits = do
  read <- forM [1..bits] $ \_ -> do
    (x, y, c) <- getRandomElement pixels
    let x' = fromInteger $ toInteger x
    let y' = fromInteger $ toInteger y
    inv <- getRandomBoolM
    let (PixelRGBA8 red green blue alpha) = pixelAt image x' y'
    let p = case c of 0 -> red .&. 1
                      1 -> green .&. 1
                      2 -> blue .&. 1
    return $ xor inv $ case p of 1 -> True
                                 0 -> False
  return $ BS.fromList read

readBytes pixels image bytes = do
  bits <- readBits pixels image (bytes * 8)
  return $ BS.realizeBitStringLazy bits

writeBits pixels image bits = forM_ (BS.toList bits) $ \bit -> do
    (x, y, c) <- getRandomElement pixels
    enc <- getRandomBoolM
    let x' = fromInteger $ toInteger x
    let y' = fromInteger $ toInteger y
    (PixelRGBA8 red green blue alpha) <- lift $ readPixel image x' y'
    let newBit = case xor enc bit of True -> 1
                                     False -> 0
    let red' = if c == 0 then (red .&. (complement 1)) .|. newBit
                         else red
    let green' = if c == 1 then (green .&. (complement 1)) .|. newBit
                           else green
    let blue' = if c == 2 then (blue .&. (complement 1)) .|. newBit
                          else blue
    lift $ writePixel image x' y' $ PixelRGBA8 red' green' blue' alpha

writeBytes pixels image bytes = writeBits pixels image (BS.bitStringLazy bytes)


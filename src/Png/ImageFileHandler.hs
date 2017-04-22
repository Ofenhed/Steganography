{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE Rank2Types #-}

module Png.ImageFileHandler (readBits, readBits_, writeBits_, getCryptoPrimitives, readSalt, pngDynamicMap, pngDynamicComponentCount, ImageFileHandlerExceptions(UnsupportedFormatException, DifferentBetweenSizeOfPrimitivesAndDataLength), CryptoPrimitive, createCryptoState, PixelInfo) where

import Codec.Picture.Png (PngSavable)
import Codec.Picture.Metadata (Metadatas)
import Control.Exception (throw, Exception)
import Control.Monad (forM, forM_, when)
import Control.Monad.ST (ST())
import Control.Monad.Trans.Class (lift)
import Crypto.RandomMonad (getRandomElement, RndST, getRandomM, randomElementsLength, RandomElementsListST(), newRandomElementST)
import Data.Array.ST (STArray(), getBounds, writeArray, readArray, newArray)
import Data.Either (isLeft)
import Data.Bits (Bits, xor, shift, (.&.), complement, (.|.))
import Data.Maybe (isNothing, isJust, fromJust)
import Data.Typeable (Typeable)
import Data.Word (Word8)
import Png.PixelStream (Pixel, getPixels)
import Data.List (find)

import qualified Codec.Picture.Types as I
import qualified Data.BitString as BS
import qualified Data.ByteString.Lazy as ByS

data CryptoPrimitive = CryptoPrimitive (Png.PixelStream.Pixel) (Bool) deriving (Show)
type CryptoStream = [CryptoPrimitive]

type PixelInfo s = (RandomElementsListST Pixel s, Maybe (STArray s (Int, Int) [Bool]), Metadatas)

createCryptoState fastMode dynamicImage = do
  let w = I.dynamicMap I.imageWidth dynamicImage
      h = I.dynamicMap I.imageHeight dynamicImage
      colors = fromIntegral $ pngDynamicComponentCount dynamicImage :: Word8
  pixels'1 <- newRandomElementST $ getPixels (fromIntegral w) (fromIntegral h) colors
  pixels'2 <- (newArray ((0, 0), (fromIntegral w - 1, fromIntegral h - 1)) $ map (\_ -> False) [1..fromIntegral colors] :: ST s (STArray s (Int, Int) [Bool]))
  return (pixels'1, if fastMode then Nothing else Just pixels'2)

getCryptoPrimitives :: PixelInfo s -> Word -> RndST s CryptoStream
getCryptoPrimitives (pixels,_,_) count = do
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
                     _ -> error "Incorrent response from getRandomM"

data ImageFileHandlerExceptions = UnsupportedFormatException |
                                  DifferentBetweenSizeOfPrimitivesAndDataLength |
                                  OutOfPixelsInSaferMode
                                  deriving (Show, Typeable)
instance Exception ImageFileHandlerExceptions

getColorAt :: I.DynamicImage -> Int -> Int -> Int -> I.Pixel16
getColorAt (I.ImageY8 i) x y c = let g = I.pixelAt i x y in fromIntegral $ [g] !! c
getColorAt (I.ImageY16 i) x y c = let g = I.pixelAt i x y in [g] !! c
getColorAt (I.ImageYA8 i) x y c = let I.PixelYA8 g _ = I.pixelAt i x y in fromIntegral $ [g] !! c
getColorAt (I.ImageYA16 i) x y c = let I.PixelYA16 g _ = I.pixelAt i x y in [g] !! c
getColorAt (I.ImageRGB8 i) x y c = let I.PixelRGB8 r g b = I.pixelAt i x y in fromIntegral $ [r, g, b] !! c
getColorAt (I.ImageRGB16 i) x y c = let I.PixelRGB16 r g b = I.pixelAt i x y in [r, g, b] !! c
getColorAt (I.ImageRGBA8 i) x y c = let I.PixelRGBA8 r g b _ = I.pixelAt i x y in fromIntegral $ [r, g, b] !! c
getColorAt (I.ImageRGBA16 i) x y c = let I.PixelRGBA16 r g b _ = I.pixelAt i x y in [r, g, b] !! c
getColorAt _ _ _ _ = throw UnsupportedFormatException

pngDynamicMap :: (forall pixel . (I.Pixel pixel, PngSavable pixel, Bits (I.PixelBaseComponent pixel)) => I.Image pixel -> a)
              -> I.DynamicImage -> a
pngDynamicMap f (I.ImageY8    i) = f i
pngDynamicMap f (I.ImageY16   i) = f i
pngDynamicMap f (I.ImageYA8   i) = f i
pngDynamicMap f (I.ImageYA16  i) = f i
pngDynamicMap f (I.ImageRGB8  i) = f i
pngDynamicMap f (I.ImageRGB16 i) = f i
pngDynamicMap f (I.ImageRGBA8 i) = f i
pngDynamicMap f (I.ImageRGBA16 i) = f i
pngDynamicMap _ _ = throw UnsupportedFormatException

pngDynamicComponentCount  :: I.DynamicImage -> Int
pngDynamicComponentCount (I.ImageYA8   i) = ((I.componentCount . \x -> I.pixelAt x 0 0) i) - 1
pngDynamicComponentCount (I.ImageYA16  i) = ((I.componentCount . \x -> I.pixelAt x 0 0) i) - 1
pngDynamicComponentCount (I.ImageRGBA8 i) = ((I.componentCount . \x -> I.pixelAt x 0 0) i) - 1
pngDynamicComponentCount (I.ImageRGBA16 i) = ((I.componentCount . \x -> I.pixelAt x 0 0) i) - 1
pngDynamicComponentCount x = pngDynamicMap (I.componentCount . \x -> I.pixelAt x 0 0) x

readBits_ primitives pixels image = BS.fromList $ read primitives
  where
  read = fmap $ \p ->
    let CryptoPrimitive (x, y, c) inv = p
        x' = fromIntegral x
        y' = fromIntegral y
        c' = fromIntegral c
        result = (getColorAt image x' y' c') .&. 1
    in xor inv $ case result of
                      1 -> True
                      0 -> False
                      _ -> error "(_ & 1) returned something else than 0 or 1."

readSalt :: PixelInfo s -> I.DynamicImage -> Word -> RndST s ByS.ByteString
readSalt pixels@(_,pixelStatus,_) image count = read [0..count-1] >>= return . ByS.pack
  where
  read = mapM $ \_ -> do
    [CryptoPrimitive (x, y, c) inv] <- getCryptoPrimitives pixels 1
    let x' = fromIntegral x
        y' = fromIntegral y
        c' = fromIntegral c
        result = getColorAt image x' y' c'
        msb = fromIntegral $ shift result (-8) :: Word8
        lsb = fromIntegral $ result :: Word8
        result' = if msb /= 0
                     then msb
                     else lsb
        result'' = if inv
                      then complement result'
                      else result'
    lift $ when (isJust pixelStatus) $ do
      prev <- readArray (fromJust pixelStatus) (fromIntegral x', fromIntegral y')
      writeArray (fromJust pixelStatus) (fromIntegral x', fromIntegral y') $ map (\_ -> True) prev
    -- This will throw away bits until a number between 0 and result'' is
    -- found. This means that this function will not only return a salt,
    -- but also salt the current crypto stream by throwing away a random
    -- number a of bits.
    _ <- getRandomM $ fromIntegral result''
    return result''

generateSeekPattern image x y = do
  let w = I.mutableImageWidth image
      h = I.mutableImageHeight image
      generateSeekPattern' distance
       | distance > max w h = []
       | otherwise = all ++ (generateSeekPattern' $ distance + 1)
        where
        left = [(x - distance :: Int, y' :: Int) | y' <- y : ([y+1..y+distance] ++ [y-1..y-distance])]
        right = [(x + distance, y') | (_, y') <- left]
        top = [(x' :: Int, y - distance :: Int) | x' <- [x-distance+1..x+distance-1]]
        bottom = [(x' :: Int, y + distance :: Int) | (x', _) <- top]
        all = [(x', y') | (x', y') <- left ++ right ++ top ++ bottom, x' < w && y' < h && min x' y' >= 0]
  generateSeekPattern' 1

findM f [] = return Nothing
findM f (x:xs) = do
  isTarget <- f x
  if isTarget
     then return $ Just x
     else findM f xs

writeBitsSafer (_, Just usedPixels, _) image@(I.MutableImage { I.mutableImageData = arr }) x y color newBit = do
  let unsafeReadPixel x' y' = I.unsafeReadPixel arr $ I.mutablePixelBaseIndex image x' y'

  originalPixel <- unsafeReadPixel x y
  let newPixel = I.mixWith (\color' value _ ->
        if color' == color
           then (value .&. (complement 1)) .|. newBit
           else value) originalPixel originalPixel

  sourceSensitivity' <- readArray usedPixels (x, y)
  let sourceSensitivity = zipWith (\prev index -> if index == color
                                                     then True
                                                     else prev) sourceSensitivity' [0..]
  writeArray usedPixels (x, y) sourceSensitivity
  if originalPixel == newPixel
    then return $ Right ()
    else do

    let validPixel = I.mixWith (\_ _ _ -> 1) originalPixel originalPixel
        overwritePixelLsb = I.mixWith (\_ value value2 -> (value .&. (complement 1)) .|. (value2 .&. 1))

        canGo pixel1 pixel2 sensitivity = do
          let possiblePixel = I.mixWith (\color' source dest -> let isUsed = sensitivity !! color'
                                                                 in if (not isUsed) || source .&. 1 == dest .&. 1
                                                                       then 1
                                                                       else 0) pixel1 pixel2
          return $ possiblePixel == validPixel

        usable (x', y') = do
          otherPixel <- unsafeReadPixel x' y'
          sourceValid <- canGo otherPixel newPixel sourceSensitivity
          if sourceValid
             then do
               targetSensitivity <- readArray usedPixels (x', y')
               targetValid <- canGo originalPixel otherPixel targetSensitivity
               return targetValid
             else return False

    foundIt <- findM usable $ generateSeekPattern image x y

    case foundIt of
         Nothing -> return $ Left "Could not find a pixel to trade with"
         Just (x', y') -> do
           otherPixel <- unsafeReadPixel x' y'
           let newOtherPixel = overwritePixelLsb otherPixel originalPixel
               newCurrentPixel = overwritePixelLsb originalPixel otherPixel
           I.writePixel image x y newCurrentPixel
           I.writePixel image x' y' newOtherPixel
           return $ Right ()


writeBits_ primitives pixels@(_, pixelStatus,_) image bits = if length primitives < (fromIntegral $ BS.length bits)
                                             then return $ Left "Got more data that crypto primitives"
                                             else do
                    merge <- forM (zipWith (\p b -> (p, b)) primitives (BS.toList bits)) inner
                    case find (\x -> isLeft x) merge of
                         Nothing -> return $ Right ()
                         Just msg -> return $ msg
  where
  inner (p, bit) = do
    let CryptoPrimitive (x, y, c) inv = p
        x' = fromIntegral x
        y' = fromIntegral y
        newBit = case xor inv bit of True -> 1
                                     False -> 0
    if isNothing pixelStatus
       then do
         pixel <- I.readPixel image x' y'
         let pixel' = I.mixWith (\color value _ ->
               if color == fromIntegral c
                  then (value .&. (complement 1)) .|. newBit
                  else value) pixel pixel
         I.writePixel image x' y' pixel'
         return $ Right ()
       else writeBitsSafer pixels image x' y' (fromIntegral c) newBit

readBits pixels image count = do
  primitives <- getCryptoPrimitives pixels count
  return $ readBits_ primitives pixels image

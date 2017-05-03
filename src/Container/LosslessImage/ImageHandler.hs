module Container.LosslessImage.ImageHandler (CryptoPrimitive, CryptoStream, getCryptoPrimitives, readSalt, readBits_, writeBits_, PixelInfo, readBits, createCryptoState, ImageFileHandlerExceptions(..)) where

import Container.LosslessImage.ImageContainer as Container
import Crypto.RandomMonad (RandomElementsListST(), RndST, newRandomElementST, getRandomElement, getRandomM)

import Control.Exception (throw, Exception)
import Control.Monad.Trans.Class (lift)
import Control.Monad.ST (ST)
import Data.List (find)
import Data.Maybe (isNothing, isJust, fromJust)
import Data.Either (isLeft)
import Data.Typeable (Typeable)
import Data.Bits (Bits, xor, shift, (.&.), complement, (.|.))
import qualified Data.BitString as BiS
import qualified Data.ByteString.Lazy as ByS
import Data.Word (Word32, Word8)
import Data.Array.ST (STArray(), getBounds, writeArray, readArray, newArray)
import Control.Monad (forM, when)

data CryptoPrimitive = CryptoPrimitive (Container.Pixel) (Bool) deriving (Show)
type CryptoStream = [CryptoPrimitive]


createCryptoState fastMode dynamicImage = do
  let (w, h, colors) = Container.getBounds dynamicImage
  pixels'1 <- newRandomElementST $ getPixels (fromIntegral w) (fromIntegral h) colors
  pixels'2 <- (newArray ((0, 0), (fromIntegral w - 1, fromIntegral h - 1)) $ map (\_ -> False) [1..fromIntegral colors] :: ST s (STArray s (Int, Int) [Bool]))
  return (pixels'1, if fastMode then Nothing else Just pixels'2)

getCryptoPrimitives :: PixelInfo s -> Word -> RndST s CryptoStream
getCryptoPrimitives (pixels,_) count = do
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

readBits_ primitives pixels image = BiS.fromList $ read primitives
  where
  read = fmap $ \p ->
    let CryptoPrimitive (x, y, c) inv = p
      in xor inv $ getPixelLsb image (x, y, c)

word32ToWord8List :: Word32 -> [Word8]
word32ToWord8List w32 = map fromIntegral [shift w32 (-24), shift w32 (-16), shift w32 (-8), w32]

readSalt :: ImageContainer const => PixelInfo s -> const -> Word -> RndST s ByS.ByteString
readSalt pixels@(_,pixelStatus) image count = read [0..count-1] >>= return . ByS.pack . concat
  where
  read = mapM $ \_ -> do
    [CryptoPrimitive (x, y, c) inv] <- getCryptoPrimitives pixels 1
    let result = getPixel image (x, y, c)
        result' = if inv
                      then complement result
                      else result
    lift $ when (isJust pixelStatus) $ do
      prev <- readArray (fromJust pixelStatus) (fromIntegral x, fromIntegral y)
      writeArray (fromJust pixelStatus) (fromIntegral x, fromIntegral y) $ zipWith (\before index -> if index == c then True else before) prev [0..]
    -- This will throw away bits until a number between 0 and result'' is
    -- found. This means that this function will not only return a salt,
    -- but also salt the current crypto stream by throwing away a random
    -- number a of bits.
    _ <- getRandomM $ fromIntegral result'
    return $ word32ToWord8List result'


staticSeekPattern width height = staticSeekPattern' (1, 0)
  where
  nextPixel (x, y) = let xBigger = abs x > abs y
                         diagonal = abs x == abs y
                         xPos = x > 0
                         yPos = y > 0
                       in case (xBigger, diagonal, xPos, yPos)
                          of
                            (True, _, True, _) -> (x, y+1)
                            (True, _, False, _) -> (x, y-1)
                            (False, True, False, True) -> (x, y-1)
                            (False, _, _, True) -> (x-1, y)
                            (False, _, _, False) -> (x+1, y)
  staticSeekPattern' prev = prev:(staticSeekPattern'' $ nextPixel prev)
  staticSeekPattern'' (x, y) = if x > width && y > height then [] else staticSeekPattern' (x, y)


generateSeekPattern width height x y = [(x' + x, y' + y) | (x', y') <- staticSeekPattern width height,
                                                           x' + x >= 0 &&
                                                           x' + x < width &&
                                                           y' + y >= 0 &&
                                                           y' + y < height]

findM f [] = return Nothing
findM f (x:xs) = do
  isTarget <- f x
  if isTarget
     then return $ Just x
     else findM f xs

--writeBitsSafer (_, Just usedPixels) image x y color newBit = do
--  originalPixel <- forM (unsafeReadPixel x y
--  let newPixel = I.mixWith (\color' value _ ->
--        if color' == color
--           then (value .&. (complement 1)) .|. newBit
--           else value) originalPixel originalPixel
--
--  sourceSensitivity' <- readArray usedPixels (x, y)
--  let sourceSensitivity = zipWith (\prev index -> if index == color
--                                                     then True
--                                                     else prev) sourceSensitivity' [0..]
--  writeArray usedPixels (x, y) sourceSensitivity
--  if originalPixel == newPixel
--    then return $ Right ()
--    else do
--
--    let validPixel = I.mixWith (\_ _ _ -> 1) originalPixel originalPixel
--        overwritePixelLsb = I.mixWith (\_ value value2 -> (value .&. (complement 1)) .|. (value2 .&. 1))
--
--        canGo pixel1 pixel2 sensitivity = do
--          let possiblePixel = I.mixWith (\color' source dest -> let isUsed = sensitivity !! color'
--                                                                 in if (not isUsed) || source .&. 1 == dest .&. 1
--                                                                       then 1
--                                                                       else 0) pixel1 pixel2
--          return $ possiblePixel == validPixel
--
--        usable (x', y') = do
--          otherPixel <- unsafeReadPixel x' y'
--          sourceValid <- canGo otherPixel newPixel sourceSensitivity
--          if sourceValid
--             then do
--               targetSensitivity <- readArray usedPixels (x', y')
--               targetValid <- canGo originalPixel otherPixel targetSensitivity
--               return targetValid
--             else return False
--
--    foundIt <- findM usable $ let (width, height) = getBoundsM image in generateSeekPattern width height x y
--
--    case foundIt of
--         Nothing -> return $ Left "Could not find a pixel to trade with"
--         Just (x', y') -> do
--           otherPixel <- unsafeReadPixel x' y'
--           let newOtherPixel = overwritePixelLsb otherPixel originalPixel
--               newCurrentPixel = overwritePixelLsb originalPixel otherPixel
--           I.writePixel image x y newCurrentPixel
--           I.writePixel image x' y' newOtherPixel
--           return $ Right ()


writeBits_ primitives pixels@(_, pixelStatus) image bits = if length primitives < (fromIntegral $ BiS.length bits)
                                             then return $ Left "Got more data that crypto primitives"
                                             else do
                    merge <- forM (zipWith (\p b -> (p, b)) primitives (BiS.toList bits)) inner
                    case find (\x -> isLeft x) merge of
                         Nothing -> return $ Right ()
                         Just msg -> return $ msg
  where
  inner (p, bit) = do
    let CryptoPrimitive (x, y, c) inv = p
    if isNothing pixelStatus
       then do
         setPixelLsb image (x, y, c) (xor inv bit)
         return $ Right ()
       --else writeBitsSafer pixels image x' y' (fromIntegral c) newBit
       else error "Safer not implemented"

readBits pixels image count = do
  primitives <- getCryptoPrimitives pixels count
  return $ readBits_ primitives pixels image

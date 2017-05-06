{-# LANGUAGE FlexibleContexts #-}

module Container.LosslessImage.ImageHandler (CryptoPrimitive, CryptoStream, getCryptoPrimitives, readSalt, readBits_, writeBits_, readBits, createCryptoState, ImageFileHandlerExceptions(..)) where

import Container.LosslessImage.ImageContainer as Container
import Crypto.RandomMonad (RandomElementsListST(), RndST, newRandomElementST, getRandomElement, getRandomM)

import Control.Exception (Exception)
import Control.Monad (forM, when, zipWithM, zipWithM_)
import Control.Monad.ST (ST)
import Control.Monad.Trans.Class (lift)
import Data.Array.ST (STArray(), getBounds, writeArray, readArray, newArray)
import Data.Bits (xor, shift, (.&.), complement, (.|.))
import Data.Either (isLeft)
import Data.List (find)
import Data.Maybe (isNothing, isJust, fromJust)
import Data.Typeable (Typeable)
import Data.Word (Word32, Word8)

import qualified Data.BitString as BiS
import qualified Data.ByteString.Lazy as ByS

data CryptoPrimitive = CryptoPrimitive (Container.Pixel) (Bool) deriving (Show)
type CryptoStream = [CryptoPrimitive]


createCryptoState fastMode dynamicImage = do
  let (w, h, colors) = Container.getBounds dynamicImage
  pixels'1 <- newRandomElementST $ getPixels (fromIntegral w) (fromIntegral h) colors
  pixels'2 <- (newArray ((0, 0), (fromIntegral w - 1, fromIntegral h - 1)) $ map (\_ -> False) [1..fromIntegral colors] :: ST s (STArray s (Int, Int) [Bool]))
  return (pixels'1, if fastMode then Nothing else Just pixels'2)

getCryptoPrimitives :: Container.PixelInfo s -> Word -> RndST s CryptoStream
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

readSalt :: ImageContainer const => Container.PixelInfo s -> const -> Word -> RndST s ByS.ByteString
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

staticSeekPattern :: Integer -> Integer -> [(Integer, Integer)]
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


generateSeekPattern :: Integer -> Integer -> Integer -> Integer -> [(Integer, Integer)]
generateSeekPattern width height x y = [(x'', y'') | (x', y') <- staticSeekPattern width height,
                                                           let x'' = x' + x; y'' = y' + y,
                                                           x'' >= 0 &&
                                                           x'' < width &&
                                                           y'' >= 0 &&
                                                           y'' < height]
--("Match: ",Nothing,[(1578,1078),(1578,1079),(1577,1079),(1576,1079)])
--Creating crypto context took 5.152052913s
--Steganography-commandline: (Nothing,4,1920,1080,1577,1078)
findM f [] = return Nothing
findM f (x:xs) = do
  isTarget <- f x
  if isTarget
     then return $ Just x
     else findM f xs

fromEitherE :: Either a a -> a
fromEitherE (Right a) = a
fromEitherE (Left a) = a

writeBitsSafer :: MutableImageContainer img => Container.PixelInfo s -> img s -> Word32 -> Word32 -> Word8 -> Bool -> ST s (Either String ())
writeBitsSafer (_, Just usedPixels) image x y color newBit = do
  currentPixel <- getPixelLsbM image (x, y, color)
  (width, height, colors) <- getBoundsM image
  usedPixelsBefore <- readArray usedPixels (fromIntegral x, fromIntegral y)
  writeArray usedPixels (fromIntegral x, fromIntegral y) $ zipWith (\before index -> if index == color then True else before) usedPixelsBefore [0..]
  if currentPixel == newBit
    then return $ Right ()
    else do
      let isMatch before other = foldl (\match (color', (before', other')) -> if not match
                                                                        then False
                                                                        else if color == color'
                                                                             then other' == Left newBit
                                                                             else fromEitherE before' == fromEitherE other' || (isLeft before' && isLeft other')) True $ zip [0..] $ zip before other
          rightLocked (x, y) = zipWithM (\index locked -> do
                       pixel <- getPixelLsbM image (x, y, index)
                       if locked
                         then return $ Right pixel
                         else return $ Left pixel) [0..]
      lockedPixelsBefore <- rightLocked (x, y) usedPixelsBefore

      let seekPattern = map (\(x, y) -> (fromInteger x, fromInteger y)) $ generateSeekPattern (fromIntegral width) (fromIntegral height) (fromIntegral x) (fromIntegral y)
      match <- findM (\(x', y') -> do
            lockedPixels' <- readArray usedPixels (fromIntegral x', fromIntegral y')
            if lockedPixels' !! fromIntegral color
               then return False
               else do
                 current <- rightLocked (x', y') lockedPixels'
                 return $ isMatch lockedPixelsBefore current) $ seekPattern
      case match of
        Nothing -> error $ show (match, length seekPattern, width, height, x, y)
        Just (x', y') -> do
          let index = [0..(fromIntegral colors-1)]
          current <- mapM (\i -> getPixelLsbM image (x, y, i)) index
          other <- zipWithM (\i new -> do
                            before <- getPixelLsbM image (x', y', i)
                            setPixelLsb image (x', y', i) new
                            return before) index current
          zipWithM_ (\i new -> setPixelLsb image (x, y, i) new) index other
          return $ Right ()



writeBits_ :: MutableImageContainer img => CryptoStream -> Container.PixelInfo s -> img s -> BiS.BitString -> ST s (Either String ())
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
       else writeBitsSafer pixels image x y c (xor inv bit)

readBits pixels image count = do
  primitives <- getCryptoPrimitives pixels count
  return $ readBits_ primitives pixels image

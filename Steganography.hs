{-# LANGUAGE FlexibleContexts #-}
import BitStringToRandom (runRndT, newRandomElementST, getRandomElement, getRandomM, randomElementsLength, replaceSeedM, RndST)
import PixelStream (getPixels, EncryptedPixel(..))
import Crypto.Pbkdf2
import qualified Data.ByteString.Lazy.Char8 as C8

import Data.Array.IO
import Control.Monad.Trans.Class
import Control.Monad
import Control.Monad.ST
import qualified Data.ByteString as BS
import Data.Word (Word8, Word32)
import qualified Data.ByteString.Lazy as LBS
import Codec.Picture.Png as Png
import Codec.Picture.Types
import qualified Data.BitString as BS
import System.Entropy
import Data.Bits
import Debug.Trace

import           System.Console.Command
  (
   Commands,Tree(Node),Command,command,withOption,withNonOption,io
  )
import           System.Console.Program (single,showUsage)
import qualified System.Console.Argument as Argument

cRed = 0 :: Word8
cGreen = 1 :: Word8
cBlue = 2 :: Word8

myCommands :: Commands IO
myCommands = Node
  (command "steganography" "A program for hiding encrypted content in a PNG image" . io $ putStrLn "No command given, try \"steganography help\"")
  [
    Node encrypt [],
    Node decrypt [],
    Node help []
  ]

namedFile :: String -> Argument.Type FilePath
namedFile name = Argument.Type { Argument.name = name, Argument.parser = Right, Argument.defaultValue = Nothing }

getRandomBoolM :: RndST s Bool
getRandomBoolM = do
  b <- getRandomM 1
  return $ case b of 1 -> True
                     0 -> False

octets :: Word32 -> [Word8]
octets w = 
    [ fromIntegral (w `shiftR` 24)
    , fromIntegral (w `shiftR` 16)
    , fromIntegral (w `shiftR` 8)
    , fromIntegral w
    ]

fromOctets :: [Word8] -> Word32
fromOctets = Prelude.foldl accum 0
  where
    accum a o = (a `shiftL` 8) .|. fromIntegral o

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


--writeBits pixels image bits = forM_ bits $ \bit -> do
--  (x, y, c) <- getRandomElement pixels
--  enc <- getRandomM 1


doEncrypt imageFile secretFile loops inputFile salt = do
  a <- BS.readFile imageFile
  secret <- LBS.readFile secretFile
  input <- LBS.readFile inputFile
  let Right (ImageRGBA8 image@(Image w h _), metadata) = decodePngWithMetadata a
  let (newImage,_) = runST $ runRndT (BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops) $ do
              pixels <- lift $ newRandomElementST $ getPixels (fromInteger . toInteger $ w) (fromInteger $ toInteger $ h)
              random <- readBytes pixels image 32
              replaceSeedM (BS.bitStringLazy $ hmacSha512Pbkdf2 secret (LBS.append random salt) loops)
              mutable <- lift $ unsafeThawImage image
              let dataLen = toInteger $ LBS.length input
              writeBytes pixels mutable (LBS.pack $ octets $ fromInteger $ dataLen)
              len <- randomElementsLength pixels
              let availLen = (quot (toInteger len) 8)
              if availLen < dataLen then error $ "The file doesn't fit in this image, the image can hold " ++ (show availLen) ++ " bytes maximum"
                                    else do
                                      writeBytes pixels mutable input
                                      result <- lift $ unsafeFreezeImage mutable
                                      return result
  let newImage' = encodePngWithMetadata metadata newImage
  if (LBS.length newImage') > 0 then LBS.writeFile imageFile $ encodePngWithMetadata metadata newImage
                                else return ()

doDecrypt imageFile secretFile loops output salt = do
  a <- BS.readFile imageFile
  secret <- LBS.readFile secretFile
  let Right (ImageRGBA8 image@(Image w h _), metadata) = decodePngWithMetadata a
  let (r,_) = runST $ runRndT (BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops) $ do
              pixels <- lift $ newRandomElementST $ getPixels (fromInteger . toInteger $ w) (fromInteger $ toInteger $ h)
              random <- readBytes pixels image 32
              replaceSeedM (BS.bitStringLazy $ hmacSha512Pbkdf2 secret (LBS.append random salt) loops)
              dataLen <- readBytes pixels image 4
              let dataLen' = toInteger $ fromOctets $ LBS.unpack dataLen
              len <- randomElementsLength pixels
              if dataLen' > ((*) 8 $ toInteger len) then return Nothing
                                                     else do
                                                       hiddenData <- readBytes pixels image dataLen'
                                                       return $ Just hiddenData
  case r of Nothing -> putStrLn "No hidden data found"
            Just x -> LBS.writeFile output x

encrypt,decrypt,help :: Command IO
encrypt = command "encrypt" "Encrypt and hide a file into a PNG file. Notice that it will overwrite the image file. SHARED-SECRET-FILE is the key. INT is the complexity of the PRNG function, higher takes longer time and is therefore more secure. INPUT-FILE is the file to be hidden in the image." $ 
          withNonOption (namedFile "IMAGE-FILE") $ \image ->
            withNonOption (namedFile "SHARED-SECRET-FILE") $ \secret -> 
              withNonOption Argument.integer $ \loops ->
                withNonOption (namedFile "INPUT-FILE") $ \file ->
                  withOption saltOption $ \salt -> io $ doEncrypt image secret loops file (C8.pack salt)

decrypt = command "decrypt" "Get data from a PNG file. Both the SHARED-SECRET-FILE and INT has to be the same as when the file was encrypted. OUTPUT-FILE will be overwritten without warning." $
          withNonOption (namedFile "IMAGE-FILE") $ \image ->
            withNonOption (namedFile "SHARED-SECRET-FILE") $ \secret -> 
              withNonOption Argument.integer $ \loops ->
                withNonOption (namedFile "OUTPUT-FILE") $ \file ->
                  withOption saltOption $ \salt -> io $ doDecrypt image secret loops file (C8.pack salt)

saltOption :: Argument.Option String
saltOption = Argument.option ['s'] ["salt"] Argument.string "" "A salt to be applied to the encryption"

help = command "help" "Show usage info" $ io (showUsage myCommands)

main = single myCommands

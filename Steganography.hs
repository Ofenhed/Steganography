{-# LANGUAGE FlexibleContexts #-}
import BitStringToRandom
  (
   runRndT, newRandomElementST, randomElementsLength, replaceSeedM, addSeedM, getRandomByteStringM
  )
import PixelStream (getPixels)
import ImageFileHandler (readBytes, writeBytes)
import AesEngine (createAes256RngState)

import Crypto.Pbkdf2

import Data.Word (Word8, Word32)
import System.Console.Command
  (
   Commands,Tree(Node),Command,command,withOption,withNonOption,io
  )
import System.Console.Program (single,showUsage)

import Codec.Picture.Png
import Codec.Picture.Types
import Control.Monad.ST
import Control.Monad.Trans.Class
import Data.Bits

import qualified Data.BitString as BS
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as C8
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

toNum = fromInteger . toInteger

createRandomStates pixels image salt = do
  random <- readBytes pixels image 256
  newPbkdfSecret <- getRandomByteStringM 256
  replaceSeedM [(BS.bitStringLazy $ hmacSha512Pbkdf2 newPbkdfSecret (LBS.append random salt) 5)]
  aesSecret <- getRandomByteStringM 32
  aesIv <- getRandomByteStringM 16
  addSeedM (createAes256RngState aesSecret aesIv)


doEncrypt imageFile secretFile loops inputFile salt = do
  a <- BS.readFile imageFile
  secret <- LBS.readFile secretFile
  input <- LBS.readFile inputFile
  let Right (ImageRGBA8 image@(Image w h _), metadata) = decodePngWithMetadata a
  let (newImage,_) = runST $ runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops)] $ do
              pixels <- lift $ newRandomElementST $ getPixels (toNum w) (toNum h)
              createRandomStates pixels image salt
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
  let (r,_) = runST $ runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops)] $ do
              pixels <- lift $ newRandomElementST $ getPixels (toNum w) (toNum h)
              createRandomStates pixels image salt
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

namedFile :: String -> Argument.Type FilePath
namedFile name = Argument.Type { Argument.name = name, Argument.parser = Right, Argument.defaultValue = Nothing }

saltOption :: Argument.Option String
saltOption = Argument.option ['s'] ["salt"] Argument.string "" "A salt to be applied to the encryption."

help = command "help" "Show usage info" $ io (showUsage myCommands)

main = single myCommands

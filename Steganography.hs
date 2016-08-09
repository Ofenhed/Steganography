{-# LANGUAGE FlexibleContexts #-}
import BitStringToRandom
  (
   runRndT, newRandomElementST, randomElementsLength, replaceSeedM, addSeedM, getRandomByteStringM
  )
import PixelStream (getPixels)
import ImageFileHandler (readBytes, writeBytes, writeBytes_, getCryptoPrimitives, readSalt)
import AesEngine (createAes256RngState)

import Crypto.Pbkdf2
import Crypto.Hash

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
import qualified Data.ByteArray as BA
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified System.Console.Argument as Argument

import Debug.Trace

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

createRandomStates pixels image@(Image width height _) salt = do
  random <- readSalt pixels image $ quot (width*height) 10
  newPbkdfSecret <- getRandomByteStringM 256
  aesSecret1 <- getRandomByteStringM 16
  replaceSeedM [(BS.bitStringLazy $ hmacSha512Pbkdf2 newPbkdfSecret (LBS.append random salt) 5)]
  aesSecret2 <- getRandomByteStringM 16
  addSeedM $ createAes256RngState $ LBS.toStrict $ LBS.append aesSecret1 aesSecret2

writeAndHash pixels image input = do
  hashPosition <- getCryptoPrimitives pixels (8 * (hashDigestSize SHA1))
  let hash' = hashInit :: Context SHA1
      writeAndHashRecursive input' h = if LBS.length input' == 0
                                          then return $ hashFinalize h
                                          else do
                                            let byte = LBS.singleton $ LBS.head input'
                                            writeBytes pixels image byte
                                            let newHash = hashUpdate h $ LBS.toStrict byte
                                            writeAndHashRecursive (LBS.tail input') newHash
  h <- writeAndHashRecursive input hash'
  writeBytes_ hashPosition image (LBS.pack $ BA.unpack h)

readUntilHash pixels image = do
  hash <- readBytes pixels image (hashDigestSize SHA1)
  let Just digest = digestFromByteString $ LBS.toStrict hash
  let hash' = hashInit :: Context SHA1
      writeUntilHashMatch h readData = if hashFinalize h == digest
                                          then return readData
                                          else do
                                            b <- readBytes pixels image 1
                                            let newHash = hashUpdate h $ LBS.toStrict b
                                            writeUntilHashMatch newHash (LBS.append readData b)
  writeUntilHashMatch hash' LBS.empty

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
              len <- randomElementsLength pixels
              let availLen = (quot (toInteger len) 8)
              if availLen < dataLen then error $ "The file doesn't fit in this image, the image can hold " ++ (show availLen) ++ " bytes maximum"
                                    else do
                                      writeAndHash pixels mutable input
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
              hiddenData <- readUntilHash pixels image
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

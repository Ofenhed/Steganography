{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}

import BitStringToRandom (runRndT, newRandomElementST, randomElementsLength)
import Codec.Picture.Png (decodePngWithMetadata, encodePngWithMetadata)
import Codec.Picture.Types (dynamicMap, imageHeight, imageWidth, unsafeThawImage, unsafeFreezeImage)
import Control.Monad.ST (runST)
import Control.Monad.Trans.Class (lift)
import Control.Monad (when)
import Crypto.Pbkdf2 (hmacSha512Pbkdf2)
import CryptoState (createPublicKeyState, readPrivateKey, addAdditionalPrivateRsaState, addAdditionalPublicRsaState, createRandomStates)
import Data.Bits (shiftR, shiftL, (.|.))
import Data.Word (Word8, Word32)
import HashedData (readUntilHash, writeAndHash)
import ImageFileHandler (pngDynamicMap, pngDynamicComponentCount)
import System.Console.Command (Commands,Tree(Node),Command,command,withOption,withNonOption,io)
import System.Console.Program (single,showUsage)

import qualified Data.BitString as BS
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified PixelStream
import qualified System.Console.Argument as Argument

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

doEncrypt imageFile secretFile loops inputFile salt pkiFile = do
  a <- BS.readFile imageFile
  secret <- LBS.readFile secretFile
  input <- LBS.readFile inputFile
  publicKeyState <- createPublicKeyState pkiFile
  let Right (dynamicImage, metadata) = decodePngWithMetadata a
      (newImage,_) = runST $ runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops)] $ pngDynamicMap (\img -> unsafeThawImage img >>= runFunc input publicKeyState (dynamicImage, metadata)) dynamicImage
  when (newImage /= LBS.empty) $ LBS.writeFile imageFile newImage
    where
    runFunc input publicKeyState (dynamicImage, metadatas) mutableImage = do
      let w = dynamicMap imageWidth dynamicImage
          h = dynamicMap imageHeight dynamicImage
      pixels <- lift $ newRandomElementST $ PixelStream.getPixels (toNum w) (toNum h) $ (fromIntegral $ pngDynamicComponentCount dynamicImage :: Word8)
      createRandomStates pixels dynamicImage salt
      addAdditionalPublicRsaState publicKeyState pixels mutableImage
      let dataLen = toInteger $ LBS.length input
      writeAndHash pixels mutableImage input
      len <- randomElementsLength pixels
      let availLen = (quot (toInteger len) 8)
      if availLen < dataLen then error $ "The file doesn't fit in this image, the image can hold " ++ (show availLen) ++ " bytes maximum"
                            else do
                              writeAndHash pixels mutableImage input
                              result <- unsafeFreezeImage mutableImage
                              return $ encodePngWithMetadata metadatas result

doDecrypt imageFile secretFile loops output salt pkiFile = do
  a <- BS.readFile imageFile
  secret <- LBS.readFile secretFile
  privateKey <- readPrivateKey pkiFile
  let Right (dynamicImage, metadata) = decodePngWithMetadata a
      w = dynamicMap imageWidth dynamicImage
      h = dynamicMap imageHeight dynamicImage
      (r,_) = runST $ runRndT [(BS.bitStringLazy $ hmacSha512Pbkdf2 secret salt loops)] $ do
              pixels <- lift $ newRandomElementST $ PixelStream.getPixels (toNum w) (toNum h) $ (fromIntegral $ pngDynamicComponentCount dynamicImage :: Word8)
              createRandomStates pixels dynamicImage salt
              addAdditionalPrivateRsaState privateKey pixels dynamicImage
              hiddenData <- readUntilHash pixels dynamicImage
              return $ Just hiddenData
  case r of Nothing -> putStrLn "No hidden data found"
            Just x -> LBS.writeFile output x

encrypt,decrypt,help :: Command IO
encrypt = command "encrypt" "Encrypt and hide a file into a PNG file. Notice that it will overwrite the image file. SHARED-SECRET-FILE is the key. INT is the complexity of the PRNG function, higher takes longer time and is therefore more secure. INPUT-FILE is the file to be hidden in the image." $ 
          withNonOption (namedFile "IMAGE-FILE") $ \image ->
            withNonOption (namedFile "SHARED-SECRET-FILE") $ \secret -> 
              withNonOption Argument.integer $ \loops ->
                withNonOption (namedFile "INPUT-FILE") $ \file ->
                  withOption saltOption $ \salt ->
                    withOption pkiFileOption $ \pkiFile -> io $ doEncrypt image secret loops file (C8.pack salt) pkiFile

decrypt = command "decrypt" "Get data from a PNG file. Both the SHARED-SECRET-FILE and INT has to be the same as when the file was encrypted. OUTPUT-FILE will be overwritten without warning." $
          withNonOption (namedFile "IMAGE-FILE") $ \image ->
            withNonOption (namedFile "SHARED-SECRET-FILE") $ \secret -> 
              withNonOption Argument.integer $ \loops ->
                withNonOption (namedFile "OUTPUT-FILE") $ \file ->
                  withOption saltOption $ \salt ->
                    withOption pkiFileOption $ \pkiFile -> io $ doDecrypt image secret loops file (C8.pack salt) pkiFile

namedFile :: String -> Argument.Type FilePath
namedFile name = Argument.Type { Argument.name = name, Argument.parser = Right, Argument.defaultValue = Nothing }

pkiFileOption :: Argument.Option String
pkiFileOption = Argument.option ['p'] ["pki"] Argument.file "" "A PEM key to use for public key cryptography. Public key for encryption and private key for decryption."

saltOption :: Argument.Option String
saltOption = Argument.option ['s'] ["salt"] Argument.string "" "A salt to be applied to the encryption."

help = command "help" "Show usage info" $ io (showUsage myCommands)

main = single myCommands

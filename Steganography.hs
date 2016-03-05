{-# LANGUAGE FlexibleContexts #-}
import BitStringToRandom (runRndT, newRandomElementST, getRandomElement, getRandomM, randomElementsLength)
import PixelStream (getPixels, EncryptedPixel(..))
import Crypto.Pbkdf2
import qualified Data.ByteString.Lazy.Char8 as C8

import Data.Array.IO
import Control.Monad.Trans.Class
import Control.Monad
import Control.Monad.ST
import qualified Data.ByteString as BS
import Data.Word (Word8)
import qualified Data.ByteString.Lazy as LBS
import Codec.Picture.Png as Png
import Codec.Picture.Types
import qualified Data.BitString as BS
import System.Entropy

import           System.Console.Command
  (
   Commands,Tree(Node),Command,command,withOption,withNonOption,io
  )
import           System.Console.Program (single,showUsage)
import qualified System.Console.Argument as Argument

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

doEncrypt image secret loops input = do
  putStrLn $ "Hello, I'm going to put secrets in " ++ image ++ " aaaaaand it's gone. The secrets, they are gone."

doDecrypt image secret loops output = do
  putStrLn $ "I could not find any secrets in " ++ image ++ " because my stupid writer hasn't implemented that function yet."

encrypt,decrypt,help :: Command IO
encrypt = command "encrypt" "Encrypt and hide a file into a PNG file. Notice that it will overwrite the image file." $ 
          withNonOption (namedFile "IMAGE-FILE") $ \image ->
            withNonOption (namedFile "SHARED-SECRET-FILE") $ \secret -> 
              withNonOption Argument.integer $ \loops ->
               withNonOption (namedFile "INPUT-FILE") $ \file -> io $ doEncrypt image secret loops file

decrypt = command "decrypt" "Get data from a PNG file" $
          withNonOption (namedFile "IMAGE-FILE") $ \image ->
            withNonOption (namedFile "SHARED-SECRET-FILE") $ \secret -> 
              withNonOption Argument.integer $ \loops ->
                withNonOption (namedFile "OUTPUT-FILE") $ \file -> io $ doDecrypt image secret loops file

help = command "help" "Show usage info" $ io (showUsage myCommands)

main = single myCommands

--requiredFile :: Argument.Type FilePath
--requiredFile = Argument.Type
--  {
--    Argument.parser = \x -> Just x
--  , Argument.name   = "FILE"
--  , Argument.defaultValue = Nothing
--  }

--main = do
--  random <- getEntropy 256
--  let (pixels,_) = runST $ runRndT (BS.bitStringLazy $ hmacSha512Pbkdf2 (C8.pack "password") (C8.pack "salt") 100000) $ do
--                   pixels <- lift $ newRandomElementST $ getPixels 1920 1080
--                   length <- randomElementsLength pixels
--                   forM [1..100] $ \_ -> do
--                     pix <- getRandomElement pixels
--                     enc <- getRandomM 1
--                     let enc' = case enc of 1 -> True
--                                            0 -> False
--                     return $ EncryptedPixel pix enc'
--  Prelude.putStrLn $ (show pixels) ++ " " ++ (show random)

--main = do
--  a <- BS.readFile "Test.png"
--  let Right (ImageRGBA8 image@(Image w h _), metadata) = decodePngWithMetadata a
--  do
--    mutable <- thawImage image
--    writePixel mutable 0 0 (PixelRGBA8 0 255 255 255)
--    pixel <- readPixel mutable 0 0
--    Prelude.putStrLn (show pixel)
--    newImage <- freezeImage mutable
--    let encodedImage = encodePngWithMetadata metadata newImage
--    BS.writeFile "Test2.png" (LBS.toStrict encodedImage)

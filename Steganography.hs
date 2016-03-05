{-# LANGUAGE FlexibleContexts #-}
import BitStringToRandom (runRndT, newRandomElementST, getRandomElement, getRandomM)
import PixelStream (getPixels, EncryptedPixel(..))
import Crypto.Pbkdf2
import qualified Data.ByteString.Lazy.Char8 as C8

import Data.Array.IO
import Control.Monad.Trans.Class
import Data.Traversable
import Control.Monad.ST
import qualified Data.ByteString as BS
import Data.Word (Word8)
import Data.ByteString.Lazy as LBS
import Codec.Picture.Png as Png
import Codec.Picture.Types
import qualified Data.BitString as BS

main = do
  let (pixels,_) = runST $ runRndT (BS.bitStringLazy $ hmacSha512Pbkdf2 (C8.pack "password") (C8.pack "salt") 10000) $ do
                   pixels <- lift $ newRandomElementST $ getPixels 1920 1080
                   forM [1..2000] $ \_ -> do
                     pix <- getRandomElement pixels
                     enc <- getRandomM 1
                     let enc' = case enc of 1 -> True
                                            0 -> False
                     return $ EncryptedPixel pix enc'
  Prelude.putStrLn $ (show $ Prelude.length pixels) ++ (show $ pixels)

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

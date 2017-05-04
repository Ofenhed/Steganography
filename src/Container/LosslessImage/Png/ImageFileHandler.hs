{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE Rank2Types #-}

module Container.LosslessImage.Png.ImageFileHandler (getColorAt, pngDynamicMap, pngDynamicComponentCount) where

import Codec.Picture.Png (PngSavable)
import Container.LosslessImage.ImageContainer (Pixel)
import Container.LosslessImage.ImageHandler (ImageFileHandlerExceptions(UnsupportedFormatException))
import Control.Exception (throw)
import Data.Bits (Bits)

import qualified Codec.Picture.Types as I

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


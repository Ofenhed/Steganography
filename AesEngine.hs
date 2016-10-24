module AesEngine (createAes256RngState) where

import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (IV, cipherInit, blockSize, nullIV, ctrCombine, ivAdd)
import Crypto.Error (CryptoFailable(CryptoPassed))
import Crypto.RandomMonad (RndState)

import qualified Data.ByteString.Lazy as ByS
import qualified Data.ByteString as BySS
import qualified Data.BitString as BS

createAes256RngState :: BySS.ByteString
                        -- ^ @aesKey@
                        -> RndState
createAes256RngState aesKey = if (BySS.length aesKey /= 32) then error "Faulty key data"
                                                           else  [BS.bitStringLazy $ generateStream True initialIv]
  where
  CryptoPassed cipher = cipherInit aesKey :: CryptoFailable AES256
  zeroes = BySS.pack $ replicate (blockSize cipher) 0
  initialIv = nullIV :: IV AES256
  generateStream firstRun iv
   | not firstRun && (iv == initialIv) = error "AES is out of entropy."
   | otherwise = let rand = ctrCombine cipher iv zeroes in ByS.append (ByS.fromStrict rand) (generateStream False $ ivAdd iv 1)

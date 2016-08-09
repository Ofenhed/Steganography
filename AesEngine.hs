module AesEngine (createAes256RngState) where

import BitStringToRandom (RndState)
import Crypto.Cipher.AES
import Crypto.Error (CryptoFailable(CryptoPassed))
import Crypto.Cipher.Types
import qualified Data.ByteString.Lazy as ByS
import qualified Data.ByteString as BySS
import qualified Data.BitString as BS

createAes256RngState :: BySS.ByteString
                        -- ^ @aesKey@
                        -> RndState
createAes256RngState aesKey = if (BySS.length aesKey /= 32) then error "Faulty key data"
                                                           else  [BS.bitStringLazy $ generateStream $ initialIv]
  where
  CryptoPassed cipher = cipherInit aesKey :: CryptoFailable AES256
  zeroes = BySS.pack $ replicate (blockSize cipher) 0
  initialIv = nullIV :: IV AES256
  generateStream iv = let rand = ctrCombine cipher iv zeroes in ByS.append (ByS.fromStrict rand) (generateStream $ ivAdd iv 1)

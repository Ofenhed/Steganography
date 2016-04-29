module AesEngine (createAes256RngState) where

import BitStringToRandom (RndState)
import Crypto.Cipher.AES
import qualified Data.ByteString.Lazy as ByS
import qualified Data.BitString as BS

createAes256RngState :: ByS.ByteString
                        -- ^ @aesKey@
                        -> ByS.ByteString
                        -- ^ @aesIv@
                        -> RndState
createAes256RngState aesKey aesIv = if (or [ByS.length aesKey /= 32, ByS.length aesIv /= 16]) then error "Faulty key data"
                                                                                               else  [BS.bitStringLazy $ generateStream $ aesIV_ $ ByS.toStrict aesIv]
  where
  aesKey' = initAES $ ByS.toStrict aesKey
  generateStream iv = let (rand, newIv) = genCounter aesKey' iv 256 in ByS.append (ByS.fromStrict rand) (generateStream newIv)

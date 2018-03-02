{-# LANGUAGE Trustworthy #-}
module Pbkdf2 (hmacSha512Pbkdf2) where

import Crypto.MAC.HMAC (initialize, update, finalize, Context(), hmacGetDigest)
import safe Crypto.Pbkdf2 (pbkdf2_iterative, pbkdf2_iterative_blocks)
import Crypto.Hash.Algorithms (SHA512)

import safe qualified Data.ByteString as BS
import qualified Data.ByteArray as BA

hmacSha512Pbkdf2 :: BS.ByteString -> BS.ByteString -> Integer -> [BS.ByteString]
hmacSha512Pbkdf2 = pbkdf2_iterative_blocks (\key -> let h = (initialize key :: Context SHA512) ; in (\msg -> let h' = update h msg in BS.pack $ BA.unpack $ hmacGetDigest $ finalize h'))

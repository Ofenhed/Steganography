module Pbkdf2 (hmacSha512Pbkdf2) where

import Crypto.MAC.HMAC (initialize, update, finalize, Context(), hmacGetDigest)
import Crypto.Pbkdf2 (pbkdf2_iterative)
import Crypto.Hash.Algorithms (SHA512)

import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteArray as BA
import qualified Data.ByteString.Lazy.Char8 as C8

hmacSha512Pbkdf2 = pbkdf2_iterative (\key d -> let h = (initialize $ C8.toStrict key :: Context SHA512) ; h' = update h $ C8.toStrict d in LBS.pack $ BA.unpack $ hmacGetDigest $ finalize h')

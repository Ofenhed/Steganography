{-# LANGUAGE Trustworthy #-}
module Pbkdf2 (hmacSha512Pbkdf2) where

import Crypto.MAC.HMAC (initialize, update, finalize, Context(), hmacGetDigest)
import safe Crypto.Pbkdf2 (pbkdf2_iterative)
import Crypto.Hash.Algorithms (SHA512)

import safe qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteArray as BA
import safe qualified Data.ByteString.Lazy.Char8 as C8

hmacSha512Pbkdf2 = pbkdf2_iterative (\key -> let h = (initialize $ C8.toStrict key :: Context SHA512) ; in (\msg -> let h' = update h $ C8.toStrict msg in LBS.pack $ BA.unpack $ hmacGetDigest $ finalize h'))

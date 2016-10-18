{-# LANGUAGE ForeignFunctionInterface #-}
module Jni where
import Steganography (doEncrypt, doDecrypt)

import Foreign.C.String (peekCAString, CString)

import qualified Data.ByteString.Lazy.Char8 as C8

encrypt :: CString -> CString -> Int -> CString -> CString -> CString -> CString -> IO ()
encrypt v1 v2 v3 v4 v5 v6 v7 = do
  v1' <- peekCAString v1
  v2' <- peekCAString v2
  let v3' = fromIntegral v3
  v4' <- peekCAString v4
  v5' <- peekCAString v5
  v6' <- peekCAString v6
  v7' <- peekCAString v7
  doEncrypt v1' v2' v3' v4' (C8.pack v5') v6' v7'

decrypt :: CString -> CString -> Int -> CString -> CString -> CString -> CString -> IO ()
decrypt v1 v2 v3 v4 v5 v6 v7= do
  v1' <- peekCAString v1
  v2' <- peekCAString v2
  let v3' = fromIntegral v3
  v4' <- peekCAString v4
  v5' <- peekCAString v5
  v6' <- peekCAString v6
  v7' <- peekCAString v7
  doDecrypt v1' v2' v3' v4' (C8.pack v5') v6' v7'

foreign export ccall "encrypt" encrypt :: CString -> CString -> Int -> CString -> CString -> CString -> CString -> IO ()
foreign export ccall "decrypt" decrypt :: CString -> CString -> Int -> CString -> CString -> CString -> CString -> IO ()


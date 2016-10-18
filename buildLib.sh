#!/bin/sh

VERSION=$(ghc --version | grep -Po '\d+\.\d+\.\d+')
cabal exec -- ghc -O2 -dynamic -shared -fPIC -o libJni.so Jni.hs module_init.c -lHSrts-ghc$VERSION

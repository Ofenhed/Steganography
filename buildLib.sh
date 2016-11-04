#!/bin/sh

VERSION=$(ghc --version | grep -Po '\d+\.\d+\.\d+')
cabal exec -- ghc -O2 -dynamic -shared -fPIC -i.:lib:src -o libJni.so lib/Jni.hs lib/module_init.c -lHSrts-ghc$VERSION

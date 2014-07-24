module Main where

import Test.Framework (defaultMain, testGroup)

import KeyTest 
import CtxTest 
import CryptoTest 

main :: IO ()
main = defaultMain
    [ testGroup "key"    KeyTest.tests
    , testGroup "ctx"    CtxTest.tests
    , testGroup "crypto" CryptoTest.tests
    ]

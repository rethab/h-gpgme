module Main where

import Test.Tasty (defaultMain, testGroup)

import KeyTest 
import CtxTest 
import CryptoTest 

main :: IO ()
main = defaultMain $ testGroup "tests"
    [ testGroup "key"    KeyTest.tests
    , testGroup "ctx"    CtxTest.tests
    , testGroup "crypto" CryptoTest.tests
    ]

module Main where

import Test.Tasty (defaultMain, testGroup)

import KeyTest 
import CtxTest 
import CryptoTest 

main :: IO ()
main = do
    passphraseCbTests <- CryptoTest.cbTests
    defaultMain $ testGroup "tests"
        [ testGroup "key"    KeyTest.tests
        , testGroup "ctx"    CtxTest.tests
        , CryptoTest.tests
        , passphraseCbTests
        ]

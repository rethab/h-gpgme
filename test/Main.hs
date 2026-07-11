module Main where

import Test.Tasty (defaultMain, testGroup)

import KeyTest
import KeyGenTest
import CtxTest
import CryptoTest

main :: IO ()
main = do
    passphraseCbTests <- CryptoTest.cbTests
    keyCbTests <- KeyTest.cbTests
    defaultMain $ testGroup "tests"
        [ testGroup "key"    KeyTest.tests
        , keyCbTests
        , testGroup "keyGen" KeyGenTest.tests
        , testGroup "ctx"    CtxTest.tests
        , CryptoTest.tests
        , passphraseCbTests
        ]

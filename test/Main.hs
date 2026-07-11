module Main where

import Test.Tasty (defaultMain, testGroup)

import KeyTest
import KeyGenTest
import CtxTest
import CryptoTest
import InternalTest

main :: IO ()
main = do
    passphraseCbTests <- CryptoTest.cbTests
    keyCbTests <- KeyTest.cbTests
    defaultMain $ testGroup "tests"
        [ testGroup "internal" InternalTest.tests
        , testGroup "key"    KeyTest.tests
        , keyCbTests
        , testGroup "keyGen" KeyGenTest.tests
        , testGroup "ctx"    CtxTest.tests
        , CryptoTest.tests
        , passphraseCbTests
        ]

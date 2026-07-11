module Main where

import Test.Tasty (defaultMain, testGroup)

import KeyTest
import KeyGenTest
import CtxTest
import CryptoTest
import InternalTest

main :: IO ()
main = do
    keyCbTests <- KeyTest.cbTests
    cryptoTests <- CryptoTest.tests
    defaultMain $ testGroup "tests"
        [ testGroup "internal" InternalTest.tests
        , testGroup "key"    KeyTest.tests
        , keyCbTests
        , testGroup "keyGen" KeyGenTest.tests
        , testGroup "ctx"    CtxTest.tests
        , cryptoTests
        ]

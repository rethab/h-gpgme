{-# LANGUAGE OverloadedStrings #-}
module KeyTest (tests) where

import Data.Maybe
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase)
import Test.HUnit

import Crypto.Gpgme
import TestUtil

tests :: [TestTree]
tests = [ testCase "get_alice_pub_from_alice" get_alice_pub_from_alice
        , testCase "get_bob_pub_from_alice" get_bob_pub_from_alice
        , testCase "alice_list_pub_keys" alice_list_pub_keys
        , testCase "alice_list_secret_keys" alice_list_secret_keys
        , testCase "get_inexistent_from_alice" get_inexistent_pub_from_alice
        ]

get_alice_pub_from_alice :: Assertion
get_alice_pub_from_alice = do
    withCtx "test/alice" "C" OpenPGP $ \ctx ->
        do key <- getKey ctx alice_pub_fpr NoSecret
           isJust key @? "missing " ++ show alice_pub_fpr

get_bob_pub_from_alice :: Assertion
get_bob_pub_from_alice = do
    withCtx "test/alice/" "C" OpenPGP $ \ctx ->
        do key <- getKey ctx bob_pub_fpr NoSecret
           isJust key @? "missing " ++ show bob_pub_fpr

alice_list_pub_keys :: Assertion
alice_list_pub_keys = do
    withCtx "test/alice" "C" OpenPGP $ \ctx ->
        do keys <- listKeys ctx NoSecret
           length keys @?= 2

alice_list_secret_keys :: Assertion
alice_list_secret_keys = do
    withCtx "test/alice" "C" OpenPGP $ \ctx ->
        do keys <- listKeys ctx WithSecret
           length keys @?= 1

get_inexistent_pub_from_alice :: Assertion
get_inexistent_pub_from_alice = do
    let inexistent_fpr = "ABCDEF"
    withCtx "test/alice/" "C" OpenPGP $ \ctx ->
        do key <- getKey ctx inexistent_fpr NoSecret
           isNothing key @? "existing " ++ show inexistent_fpr

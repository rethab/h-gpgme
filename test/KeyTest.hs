{-# LANGUAGE OverloadedStrings #-}
module KeyTest (tests) where

import Data.Maybe
import Test.Framework.Providers.HUnit
import Test.HUnit

import Crypto.Gpgme

tests = [ testCase "get_alice_pub_from_alice" get_alice_pub_from_alice
        , testCase "get_bob_pub_from_alice" get_bob_pub_from_alice
        , testCase "alice_list_pub_keys" alice_list_pub_keys
        , testCase "alice_list_secret_keys" alice_list_secret_keys
        , testCase "get_inexistent_from_alice" get_inexistent_pub_from_alice
        , testCase "with_inexistent_from_alice" with_inexistent_from_alice
        , testCase "with_alice_pub_from_alice" with_alice_pub_from_alice
        ]

get_alice_pub_from_alice :: Assertion
get_alice_pub_from_alice = do
    let alice_pub_fpr = "EAACEB8A"
    withCtx "test/alice" "C" OpenPGP $ \ctx ->
        do key <- getKey ctx alice_pub_fpr NoSecret
           isJust key @? "missing " ++ show alice_pub_fpr
           freeKey (fromJust key)

get_bob_pub_from_alice :: Assertion
get_bob_pub_from_alice = do
    let bob_pub_fpr = "6C4FB8F2"
    withCtx "test/alice/" "C" OpenPGP $ \ctx ->
        do key <- getKey ctx bob_pub_fpr NoSecret
           isJust key @? "missing " ++ show bob_pub_fpr
           freeKey (fromJust key)

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

with_inexistent_from_alice :: Assertion
with_inexistent_from_alice = do
    let inexistent_fpr = "ABCDEF"
    withCtx "test/alice/" "C" OpenPGP $ \ctx ->
        do res <- withKey ctx inexistent_fpr NoSecret $ \_ -> do
                    assertFailure "should not run action"
           isNothing res @? "should be nothing"

with_alice_pub_from_alice :: Assertion
with_alice_pub_from_alice = do
    let alice_pub_fpr = "EAACEB8A"
    withCtx "test/alice/" "C" OpenPGP $ \ctx ->
        do res <- withKey ctx alice_pub_fpr NoSecret $ \_ -> do
                    return ("foo" :: String)
           isJust res @? "should be just"
           fromJust res @?= "foo"

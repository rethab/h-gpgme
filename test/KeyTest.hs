{-# LANGUAGE OverloadedStrings #-}
module KeyTest (tests) where

import Data.Maybe
import Test.Framework.Providers.HUnit
import Test.HUnit

import Crypto.Gpgme
import Crypto.Gpgme.Key

tests = [ testCase "get_alice_pub_from_alice" get_alice_pub_from_alice
        , testCase "get_bob_pub_from_alice" get_bob_pub_from_alice
        , testCase "alice_list_pub_keys" alice_list_pub_keys
        , testCase "alice_list_secret_keys" alice_list_secret_keys
        , testCase "get_inexistent_from_alice" get_inexistent_pub_from_alice
        , testCase "check_alice_pub_user_ids" check_alice_pub_user_ids
        , testCase "check_alice_pub_subkeys" check_alice_pub_subkeys
        ]

alice_pub_fpr, bob_pub_fpr :: Fpr
alice_pub_fpr = "EAACEB8A"
bob_pub_fpr = "6C4FB8F2"

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
           let keyIds = [["163EC68CCF3FBF8E","DD2469546C4FB8F2"],
                         ["6B9809775CF91391","3BA69AA2EAACEB8A"]]
           map (map subkeyKeyId . keySubKeys) keys @?= keyIds

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

check_alice_pub_user_ids :: Assertion
check_alice_pub_user_ids = do
    withCtx "test/alice" "C" OpenPGP $ \ctx ->
        do Just key <- getKey ctx alice_pub_fpr NoSecret
           let uids = keyUserIds key
           length uids @?= 1
           let kuid = head uids
               uid = keyuserId kuid
           keyuserValidity kuid @?= ValidityUltimate
           userId uid @?= "Alice (Test User A) <alice@email.com>"
           userName uid @?= "Alice"
           userEmail uid @?= "alice@email.com"
           userComment uid @?= "Test User A"

check_alice_pub_subkeys :: Assertion
check_alice_pub_subkeys = do
    withCtx "test/alice" "C" OpenPGP $ \ctx ->
        do Just key <- getKey ctx alice_pub_fpr NoSecret
           let subs = keySubKeys key
           length subs @?= 2
           let sub = head subs
           subkeyAlgorithm sub @?= Rsa
           subkeyLength sub @?= 2048
           subkeyKeyId sub @?= "6B9809775CF91391"

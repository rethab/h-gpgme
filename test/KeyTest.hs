module KeyTest (tests) where

import Data.Maybe
import Test.Framework.Providers.HUnit
import Test.HUnit

import Crypto.Gpgme

tests = [ testCase "get_alice_pub_from_alice" get_alice_pub_from_alice
        , testCase "get_bob_pub_from_alice" get_bob_pub_from_alice
        , testCase "get_inexistent_from_alice" get_inexistent_pub_from_alice
        , testCase "with_inexistent_from_alice" get_inexistent_pub_from_alice
        ]

get_alice_pub_from_alice = do
    let alice_pub_fpr = "EAACEB8A"
    withCtx "test/alice" "C" openPGP $ \ctx ->
        do key <- getKey ctx alice_pub_fpr noSecret
           isJust key @? "missing " ++ alice_pub_fpr
           freeKey (fromJust key)

get_bob_pub_from_alice = do
    let bob_pub_fpr = "6C4FB8F2"
    withCtx "test/alice/" "C" openPGP $ \ctx ->
        do key <- getKey ctx bob_pub_fpr noSecret
           isJust key @? "missing " ++ bob_pub_fpr
           freeKey (fromJust key)

get_inexistent_pub_from_alice = do
    let inexistent_fpr = "ABCDEF"
    withCtx "test/alice/" "C" openPGP $ \ctx ->
        do key <- getKey ctx inexistent_fpr noSecret
           isNothing key @? "existing " ++ inexistent_fpr

with_inexistent_from_alice = do
    let inexistent_fpr = "ABCDEF"
    withCtx "test/alice/" "C" openPGP $ \ctx ->
        do res <- withKey ctx inexistent_fpr noSecret $ \key -> do
                    assertFailure "should not run action"
           isNothing res @? "should be nothing"

with_alice_pub_from_alice = do
    let alice_pub_fpr = "EAACEB8A"
    withCtx "test/alice/" "C" openPGP $ \ctx ->
        do res <- withKey ctx alice_pub_fpr noSecret $ \key -> do
                    return "foo"
           isJust res @? "should be just"
           fromJust res @?= "foo"

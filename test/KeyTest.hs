{-# LANGUAGE OverloadedStrings #-}
module KeyTest (tests) where

import Data.Maybe
import Data.List
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase)
import Test.HUnit

import System.FilePath    ((</>))
import System.Directory   ( removeDirectoryRecursive
                          , createDirectory
                          , listDirectory
                          , copyFile
                          )

import Crypto.Gpgme
import TestUtil

tests :: [TestTree]
tests = [ testCase "get_alice_pub_from_alice" get_alice_pub_from_alice
        , testCase "get_bob_pub_from_alice" get_bob_pub_from_alice
        , testCase "alice_list_pub_keys" alice_list_pub_keys
        , testCase "alice_list_secret_keys" alice_list_secret_keys
        , testCase "get_inexistent_from_alice" get_inexistent_pub_from_alice
        , testCase "check_alice_pub_user_ids" check_alice_pub_user_ids
        , testCase "check_alice_pub_subkeys" check_alice_pub_subkeys
        , testCase "remove_alice_key_prompt" remove_alice_key
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

remove_alice_key :: Assertion
remove_alice_key = do
  tmpDir <- createTemporaryTestDir "remove_alice_key"

  -- Copy alice's key into temporary directory so we can safely remove it
  let alice_tmpDir = tmpDir </> "alice"
  createDirectory $ alice_tmpDir
  alice_files <- listDirectory "test/alice"
  mapM_ (\f -> copyFile ("test/alice" </> f) (tmpDir </> "alice" </> f))
    $ filter (\f -> (not $ isPrefixOf "S.gpg-agent" f)
                 && f /= "private-keys-v1.d"
                 && f /= ".gpg-v21-migrated"
                 && f /= "random_seed"
             ) alice_files

  withCtx (tmpDir </> "alice") "C" OpenPGP $ \ctx ->
    do key <- getKey ctx alice_pub_fpr WithSecret
       start_num <- listKeys ctx WithSecret >>= \l -> return $ length l
       start_num @?= 1
       ret <- removeKey ctx (fromJust key) WithSecret
       end_num <- listKeys ctx WithSecret >>= \l -> return $ length l
       end_num @?= 0
       ret @?= Nothing

  -- Cleanup test
  removeDirectoryRecursive tmpDir

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
tests = [ testCase "getAlicePubFromAlice" getAlicePubFromAlice
        , testCase "getBobPubFromAlice" getBobPubFromAlice
        , testCase "aliceListPubKeys" aliceListPubKeys
        , testCase "aliceListSecretKeys" aliceListSecretKeys
        , testCase "getInexistentFromAlice" getInexistentPubFromAlice
        , testCase "checkAlicePubUserIds" checkAlicePubUserIds
        , testCase "checkAlicePubSubkeys" checkAlicePubSubkeys
        , testCase "removeAliceKey" removeAliceKey
        ]

getAlicePubFromAlice :: Assertion
getAlicePubFromAlice = do
    withCtx "test/alice" "C" OpenPGP $ \ctx ->
        do key <- getKey ctx alicePubFpr NoSecret
           isJust key @? "missing " ++ show alicePubFpr

getBobPubFromAlice :: Assertion
getBobPubFromAlice = do
    withCtx "test/alice/" "C" OpenPGP $ \ctx ->
        do key <- getKey ctx bobPubFpr NoSecret
           isJust key @? "missing " ++ show bobPubFpr

aliceListPubKeys :: Assertion
aliceListPubKeys = do
    withCtx "test/alice" "C" OpenPGP $ \ctx ->
        do keys <- listKeys ctx NoSecret
           length keys @?= 2
           let keyIds = [["163EC68CCF3FBF8E","DD2469546C4FB8F2"],
                         ["6B9809775CF91391","3BA69AA2EAACEB8A"]]
           map (map subkeyKeyId . keySubKeys) keys @?= keyIds

aliceListSecretKeys :: Assertion
aliceListSecretKeys = do
    withCtx "test/alice" "C" OpenPGP $ \ctx ->
        do keys <- listKeys ctx WithSecret
           length keys @?= 1

getInexistentPubFromAlice :: Assertion
getInexistentPubFromAlice = do
    let inexistentFpr = "ABCDEF"
    withCtx "test/alice/" "C" OpenPGP $ \ctx ->
        do key <- getKey ctx inexistentFpr NoSecret
           isNothing key @? "existing " ++ show inexistentFpr

checkAlicePubUserIds :: Assertion
checkAlicePubUserIds = do
    withCtx "test/alice" "C" OpenPGP $ \ctx ->
        do Just key <- getKey ctx alicePubFpr NoSecret
           let uids = keyUserIds key
           length uids @?= 1
           let kuid = head uids
               uid = keyuserId kuid
           keyuserValidity kuid @?= ValidityUltimate
           userId uid @?= "Alice (Test User A) <alice@email.com>"
           userName uid @?= "Alice"
           userEmail uid @?= "alice@email.com"
           userComment uid @?= "Test User A"

checkAlicePubSubkeys :: Assertion
checkAlicePubSubkeys = do
    withCtx "test/alice" "C" OpenPGP $ \ctx ->
        do Just key <- getKey ctx alicePubFpr NoSecret
           let subs = keySubKeys key
           length subs @?= 2
           let sub = head subs
           subkeyAlgorithm sub @?= Rsa
           subkeyLength sub @?= 2048
           subkeyKeyId sub @?= "6B9809775CF91391"
           subkeyFpr sub @?= "3F10159E56ECB494ED42EFA36B9809775CF91391"

removeAliceKey :: Assertion
removeAliceKey = do
  tmpDir <- createTemporaryTestDir "removeAliceKey"

  -- Copy alice's key into temporary directory so we can safely remove it
  let aliceTmpDir = tmpDir </> "alice"
  createDirectory aliceTmpDir
  aliceFiles <- listDirectory "test/alice"
  mapM_ (\f -> copyFile ("test/alice" </> f) (tmpDir </> "alice" </> f))
    $ filter (\f -> not ("S.gpg-agent" `isPrefixOf` f)
                 && f /= "private-keys-v1.d"
                 && f /= ".gpg-v21-migrated"
                 && f /= "randomSeed"
             ) aliceFiles

  withCtx (tmpDir </> "alice") "C" OpenPGP $ \ctx ->
    do key <- getKey ctx alicePubFpr WithSecret
       startNum <- listKeys ctx WithSecret >>= \l -> return $ length l
       startNum @?= 1
       ret <- removeKey ctx (fromJust key) (RemoveKeyFlags True True)
       endNum <- listKeys ctx WithSecret >>= \l -> return $ length l
       endNum @?= 0
       ret @?= Nothing

  -- Cleanup test
  removeDirectoryRecursive tmpDir

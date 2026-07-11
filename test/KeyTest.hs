{-# LANGUAGE OverloadedStrings #-}
module KeyTest (tests, cbTests) where

import qualified Data.ByteString as BS
import Data.Maybe
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)
import Test.HUnit

import System.FilePath    ((</>))
import System.Directory   (removeDirectoryRecursive)

import Crypto.Gpgme
import TestUtil

tests :: [TestTree]
tests = [ testCase "getAlicePubFromAlice" getAlicePubFromAlice
        , testCase "getBobPubFromAlice" getBobPubFromAlice
        , testCase "aliceListPubKeys" aliceListPubKeys
        , testCase "aliceListSecretKeys" aliceListSecretKeys
        , testCase "aliceSearchPubKeys" aliceSearchPubKeys
        , testCase "getInexistentFromAlice" getInexistentPubFromAlice
        , testCase "checkAlicePubUserIds" checkAlicePubUserIds
        , testCase "checkAlicePubSubkeys" checkAlicePubSubkeys
        , testCase "removeAliceKey" removeAliceKey
        , testCase "readFromFileWorks" readFromFileWorks
        , testCase "readFromFileDoesn'tExist" readFromFileDoesn'tExist
        , testCase "readFromBytesWorks" readFromBytesWorks
        , testCase "exportAlicePubArmored" exportAlicePubArmored
        , testCase "exportImportRoundtrip" exportImportRoundtrip
        , testCase "exportInexistentIsEmpty" exportInexistentIsEmpty
        , testCase "exportAllKeys" exportAllKeys
        , testCase "exportMinimal" exportMinimal
        ]

cbTests :: IO TestTree
cbTests = do
    supported <- withCtx "test/alice" "C" OpenPGP $ \ctx ->
        return $ isPassphraseCbSupported ctx
    if supported
       then return $ testGroup "key-passphrase-cb"
                [ testCase "exportAliceSecretArmored" exportAliceSecretArmored ]
       else return $ testGroup "key-passphrase-cb" []

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

aliceSearchPubKeys :: Assertion
aliceSearchPubKeys = do
    withCtx "test/alice" "C" OpenPGP $ \ctx ->
        do keys <- searchKeys ctx NoSecret "alice@email.com"
           length keys @?= 1
           let keyIds = [["6B9809775CF91391","3BA69AA2EAACEB8A"]]
           map (map subkeyKeyId . keySubKeys) keys @?= keyIds

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
           case keyUserIds key of
             [kuid] -> do
               let uid = keyuserId kuid
               keyuserValidity kuid @?= ValidityUltimate
               userId uid @?= "Alice (Test User A) <alice@email.com>"
               userName uid @?= "Alice"
               userEmail uid @?= "alice@email.com"
               userComment uid @?= "Test User A"
             uids -> assertFailure $
               "expected exactly one user id, got " ++ show (length uids)

checkAlicePubSubkeys :: Assertion
checkAlicePubSubkeys = do
    withCtx "test/alice" "C" OpenPGP $ \ctx ->
        do Just key <- getKey ctx alicePubFpr NoSecret
           case keySubKeys key of
             [sub, _] -> do
               subkeyAlgorithm sub @?= Rsa
               subkeyLength sub @?= 2048
               subkeyKeyId sub @?= "6B9809775CF91391"
               subkeyFpr sub @?= "3F10159E56ECB494ED42EFA36B9809775CF91391"
             subs -> assertFailure $
               "expected exactly two subkeys, got " ++ show (length subs)

removeAliceKey :: Assertion
removeAliceKey = do
  tmpDir <- createTemporaryTestDir "removeAliceKey"

  let aliceTmpDir = tmpDir </> "alice"
  copyGpgHomedir "test/alice" aliceTmpDir

  withCtx aliceTmpDir "C" OpenPGP $ \ctx ->
    do key <- getKey ctx alicePubFpr WithSecret
       startNum <- listKeys ctx WithSecret >>= \l -> return $ length l
       startNum @?= 1
       ret <- removeKey ctx (fromJust key) (RemoveKeyFlags True True)
       endNum <- listKeys ctx WithSecret >>= \l -> return $ length l
       endNum @?= 0
       ret @?= Nothing

  removeDirectoryRecursive tmpDir

readFromFileWorks :: Assertion
readFromFileWorks = do
    withCtx "test/real-person" "C" OpenPGP $ \ctx -> do
      mRet <- importKeyFromFile ctx "test/real-person/real-person.key"
      mRet @?= Nothing

readFromFileDoesn'tExist :: Assertion
readFromFileDoesn'tExist = do
    withCtx "test/real-person" "C" OpenPGP $ \ctx -> do
      mRet <- importKeyFromFile ctx "this-file-doesn't-exist"
      isJust mRet @? "shouldn't be able to read this file"

exportAlicePubArmored :: Assertion
exportAlicePubArmored =
    withCtx "test/alice" "C" OpenPGP $ \ctx -> do
        setArmor True ctx
        key <- fromRight <$> exportKey ctx alicePubFpr
        ("-----BEGIN PGP PUBLIC KEY BLOCK-----" `BS.isPrefixOf` key)
            @? "exported key must be armored"

exportImportRoundtrip :: Assertion
exportImportRoundtrip = do
    key <- withCtx "test/alice" "C" OpenPGP $ \ctx ->
        fromRight <$> exportKey ctx alicePubFpr
    tmpDir <- createTemporaryTestDir "exportImportRoundtrip"
    withCtx tmpDir "C" OpenPGP $ \ctx -> do
        mErr <- importKeyFromBytes ctx key
        mErr @?= Nothing
        imported <- getKey ctx alicePubFpr NoSecret
        isJust imported @? "imported key should be present"
    removeDirectoryRecursive tmpDir

exportInexistentIsEmpty :: Assertion
exportInexistentIsEmpty =
    withCtx "test/alice" "C" OpenPGP $ \ctx -> do
        key <- fromRight <$> exportKey ctx "ABCDEF"
        key @?= BS.empty

exportAllKeys :: Assertion
exportAllKeys =
    withCtx "test/alice" "C" OpenPGP $ \ctx -> do
        single <- fromRight <$> exportKeys ctx [] [alicePubFpr]
        all' <- fromRight <$> exportKeys ctx [] []
        (BS.length all' > BS.length single)
            @? "exporting all keys must yield more than a single key"

exportMinimal :: Assertion
exportMinimal =
    withCtx "test/bob" "C" OpenPGP $ \ctx -> do
        full <- fromRight <$> exportKeys ctx [] [alicePubFpr]
        minimal <- fromRight <$> exportKeys ctx [ExportMinimal] [alicePubFpr]
        not (BS.null minimal) @? "minimal export must not be empty"
        (BS.length minimal <= BS.length full)
            @? "minimal export must not be larger than the full export"

exportAliceSecretArmored :: Assertion
exportAliceSecretArmored =
    withCtx "test/alice" "C" OpenPGP $ \ctx -> do
        setPassphraseCallback ctx (Just (\_ _ _ -> return (Just "alice123")))
        setArmor True ctx
        key <- fromRight <$> exportSecretKey ctx alicePubFpr
        ("-----BEGIN PGP PRIVATE KEY BLOCK-----" `BS.isPrefixOf` key)
            @? "exported secret key must be armored"

readFromBytesWorks :: Assertion
readFromBytesWorks = do
    key <- BS.readFile "test/real-person/real-person.key"
    tmpDir <- createTemporaryTestDir "readFromBytesWorks"
    withCtx tmpDir "C" OpenPGP $ \ctx -> do
      before <- getKey ctx realPersonPubFpr NoSecret
      isNothing before @? "key shouldn't be present before import"
      mRet <- importKeyFromBytes ctx key
      mRet @?= Nothing
      after <- getKey ctx realPersonPubFpr NoSecret
      isJust after @? "key should be present after import"
    removeDirectoryRecursive tmpDir

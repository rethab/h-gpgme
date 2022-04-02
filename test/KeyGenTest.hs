{-# LANGUAGE OverloadedStrings #-}
module KeyGenTest (tests) where

import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase)
import Test.HUnit

import Text.Email.Validate
import System.FilePath    ((</>))
import System.Directory   ( removeDirectoryRecursive )
import System.IO          ( hPutStr
                          , hPutStrLn
                          , IOMode (..)
                          , withFile
                          , hGetContents
                          )
import Data.Time.Calendar
import Data.Time.Clock
import Data.Default
import Data.List          ( isPrefixOf )
import Data.ByteString.Char8    ( unpack )

import            Crypto.Gpgme
import qualified  Crypto.Gpgme.Key.Gen as G
import TestUtil

tests :: [TestTree]
tests = [ testCase "allGenKeyParameters" allGenKeyParameters
        , testCase "expireDateDays" expireDateDays
        , testCase "expireDateWeeks" expireDateWeeks
        , testCase "expireDateMonths" expireDateMonths
        , testCase "expireDateYears" expireDateYears
        , testCase "expireDateSeconds" expireDateSeconds
        , testCase "creationDateSeconds" creationDateSeconds
        , testCase "genKeyNoCi" genKey
        , testCase "progressCallbackNoCi" progressCallback
        ]

-- For getting values from Either
errorOnLeft :: Either String a -> a
errorOnLeft (Right x) = x
errorOnLeft (Left s)  = error s

-- Test parameter list generation for generating keys
allGenKeyParameters :: Assertion
allGenKeyParameters =
  let params = (def :: G.GenKeyParams) -- G.defaultGenKeyParams
        { G.keyType = Just Dsa
        , G.keyLength = Just $ errorOnLeft $ G.bitSize 1024
        , G.keyGrip = "123abc"
        , G.keyUsage = Just $ (def :: G.UsageList) {
            G.encrypt = Just G.Encrypt
          , G.sign = Just G.Sign
          , G.auth = Just G.Auth
          }
        , G.subkeyType = Just ElgE
        , G.subkeyLength = Just $ errorOnLeft $ G.bitSize 1024
        , G.passphrase = "easy to guess"
        , G.nameReal = "Foo Bar"
        , G.nameComment = "A great comment"
        , G.nameEmail = Just $ errorOnLeft $ validate "foo@example.com"
        , G.expireDate = Just $ G.ExpireT $ UTCTime (fromGregorian 2050 8 15) 52812
        , G.creationDate = Just $ G.CreationT $
            UTCTime (fromGregorian 2040 8 16) 52813
        , G.preferences = "Some preference"
        , G.revoker = "RSA:fpr sensitive"
        , G.keyserver = "https://keyserver.com/"
        , G.handle = "Key handle here"
        }
  in G.toParamsString params @?=
      "<GnupgKeyParms format=\"internal\">\n\
      \Key-Type: DSA\n\
      \Key-Length: 1024\n\
      \Key-Grip: 123abc\n\
      \Key-Usage: encrypt,sign,auth\n\
      \Subkey-Type: ELG-E\n\
      \Subkey-Length: 1024\n\
      \Passphrase: easy to guess\n\
      \Name-Real: Foo Bar\n\
      \Name-Comment: A great comment\n\
      \Name-Email: foo@example.com\n\
      \Expire-Date: 20500815T144012\n\
      \Creation-Date: 20400816T144013\n\
      \Preferences: Some preference\n\
      \Revoker: RSA:fpr sensitive\n\
      \Keyserver: https://keyserver.com/\n\
      \Handle: Key handle here\n\
      \</GnupgKeyParms>\n"

genKey :: Assertion
genKey = do
  tmpDir <- createTemporaryTestDir "genKey"

  ret <- withCtx tmpDir "C" OpenPGP $ \ctx -> do
    let params = (def :: G.GenKeyParams)
                { G.keyType = Just Dsa
                , G.keyLength = Just $ errorOnLeft $ G.bitSize 1024
                , G.rawParams =
                  "Subkey-Type: ELG-E\n\
                  \Subkey-Length: 1024\n\
                  \Name-Real: Joe Tester\n\
                  \Name-Comment: (pp=abc)\n\
                  \Name-Email: joe@foo.bar\n\
                  \Expire-Date: 0\n\
                  \Passphrase: abc\n"
                }

    G.genKey ctx params
  -- Cleanup temporary directory
  removeDirectoryRecursive tmpDir
  either
    (\l -> assertFailure $ "Left was return value " ++ show l)
    (\r -> assertBool ("Fingerprint ("
                        ++ unpack r
                        ++ ") starts with '0x' indicating it is actually a pointer.")
      (not $ isPrefixOf "0x" (unpack r))) ret

-- Other ExpireDate to string possibilities
expireDateDays :: Assertion
expireDateDays =
  let (Just p) = G.toPositive 10
      params = (def :: G.GenKeyParams) {
          G.expireDate = Just $ G.ExpireD p
        }
  in G.toParamsString params @?=
      "<GnupgKeyParms format=\"internal\">\n\
      \Key-Type: default\n\
      \Expire-Date: 10d\n\
      \</GnupgKeyParms>\n"

expireDateWeeks :: Assertion
expireDateWeeks =
  let (Just p) = G.toPositive 10
      params = (def :: G.GenKeyParams) {
          G.expireDate = Just $ G.ExpireW p
        }
  in G.toParamsString params @?=
      "<GnupgKeyParms format=\"internal\">\n\
      \Key-Type: default\n\
      \Expire-Date: 10w\n\
      \</GnupgKeyParms>\n"

expireDateMonths :: Assertion
expireDateMonths =
  let (Just p) = G.toPositive 10
      params = (def :: G.GenKeyParams) {
          G.expireDate = Just $ G.ExpireM p
        }
  in G.toParamsString params @?=
      "<GnupgKeyParms format=\"internal\">\n\
      \Key-Type: default\n\
      \Expire-Date: 10m\n\
      \</GnupgKeyParms>\n"

expireDateYears :: Assertion
expireDateYears =
  let (Just p) = G.toPositive 10
      params = (def :: G.GenKeyParams) {
          G.expireDate = Just $ G.ExpireY p
        }
  in G.toParamsString params @?=
      "<GnupgKeyParms format=\"internal\">\n\
      \Key-Type: default\n\
      \Expire-Date: 10y\n\
      \</GnupgKeyParms>\n"

expireDateSeconds :: Assertion
expireDateSeconds =
  let (Just p) = G.toPositive 123456
      params = (def :: G.GenKeyParams) {
          G.expireDate = Just $ G.ExpireS p
        }
  in G.toParamsString params @?=
      "<GnupgKeyParms format=\"internal\">\n\
      \Key-Type: default\n\
      \Expire-Date: seconds=123456\n\
      \</GnupgKeyParms>\n"

creationDateSeconds :: Assertion
creationDateSeconds =
  let (Just p) = G.toPositive 123456
      params = (def :: G.GenKeyParams) {
          G.creationDate = Just $ G.CreationS p
        }
  in G.toParamsString params @?=
      "<GnupgKeyParms format=\"internal\">\n\
      \Key-Type: default\n\
      \Creation-Date: seconds=123456\n\
      \</GnupgKeyParms>\n"

progressCallback :: Assertion
progressCallback = do
  tmpDir <- createTemporaryTestDir "progress_callback"

  -- Setup context
  genRet <- withCtx tmpDir "C" OpenPGP $ \ctx -> do
    -- Setup generation parameters
    let params = (def :: G.GenKeyParams)
                { G.keyType   = Just Rsa
                , G.keyLength = Just $ errorOnLeft $ G.bitSize 2048
                , G.nameReal  = "Joe Tester"
                , G.nameEmail = Just $ errorOnLeft $ validate "joe@foo.bar"
                , G.passphrase  = "abc"
                }

        -- Setup callback which writes to temporary file.
        testProgressCb what char cur total =
          withFile (tmpDir </> "testProgress.log") AppendMode (\h -> do
            hPutStr h ("what: " ++ what)
            hPutStr h (" char: " ++ show char)
            hPutStr h (" cur: " ++ show cur)
            hPutStr h (" total: " ++ show total)
            hPutStrLn h "")

    setProgressCallback ctx (Just testProgressCb)

    -- Run key generation
    G.genKey ctx params

  -- Make sure the file has some evidence of progress notifications
  ret <- withFile (tmpDir </> "testProgress.log") ReadMode (\h -> do
    contents <- hGetContents h
    not (null (lines contents)) @? "No lines in progress file")

  -- Cleanup test
  removeDirectoryRecursive tmpDir
  assertBool ("Left was return value: " ++ show ret) (either (const False) (const True) genRet)
  return ret

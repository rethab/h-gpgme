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

import            Crypto.Gpgme
import qualified  Crypto.Gpgme.Key.Gen as G
import TestUtil

tests :: [TestTree]
tests = [ testCase "all_gen_key_parameters" all_gen_key_parameters
        , testCase "expire_date_days" expire_date_days
        , testCase "expire_date_weeks" expire_date_weeks
        , testCase "expire_date_months" expire_date_months
        , testCase "expire_date_years" expire_date_years
        , testCase "expire_date_seconds" expire_date_seconds
        , testCase "creation_date_seconds" creation_date_seconds
        , testCase "gen_key_no_travis" gen_key
        , testCase "progress_callback_no_travis" progress_callback
        ]

-- For getting values from Either
errorOnLeft :: Either String a -> a
errorOnLeft (Right x) = x
errorOnLeft (Left s)  = error s

-- Test parameter list generation for generating keys
all_gen_key_parameters :: Assertion
all_gen_key_parameters =
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
  in (G.toParamsString params) @?=
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

gen_key :: Assertion
gen_key = do
  tmpDir <- createTemporaryTestDir "gen_key"

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
  ret @?= Nothing


-- Other ExpireDate to string possibilities
expire_date_days :: Assertion
expire_date_days =
  let (Just p) = G.toPositive 10
      params = (def :: G.GenKeyParams) {
          G.expireDate = Just $ G.ExpireD p
        }
  in (G.toParamsString params) @?=
      "<GnupgKeyParms format=\"internal\">\n\
      \Key-Type: default\n\
      \Expire-Date: 10d\n\
      \</GnupgKeyParms>\n"

expire_date_weeks :: Assertion
expire_date_weeks =
  let (Just p) = G.toPositive 10
      params = (def :: G.GenKeyParams) {
          G.expireDate = Just $ G.ExpireW p
        }
  in (G.toParamsString params) @?=
      "<GnupgKeyParms format=\"internal\">\n\
      \Key-Type: default\n\
      \Expire-Date: 10w\n\
      \</GnupgKeyParms>\n"

expire_date_months :: Assertion
expire_date_months =
  let (Just p) = G.toPositive 10
      params = (def :: G.GenKeyParams) {
          G.expireDate = Just $ G.ExpireM p
        }
  in (G.toParamsString params) @?=
      "<GnupgKeyParms format=\"internal\">\n\
      \Key-Type: default\n\
      \Expire-Date: 10m\n\
      \</GnupgKeyParms>\n"

expire_date_years :: Assertion
expire_date_years =
  let (Just p) = G.toPositive 10
      params = (def :: G.GenKeyParams) {
          G.expireDate = Just $ G.ExpireY p
        }
  in (G.toParamsString params) @?=
      "<GnupgKeyParms format=\"internal\">\n\
      \Key-Type: default\n\
      \Expire-Date: 10y\n\
      \</GnupgKeyParms>\n"

expire_date_seconds :: Assertion
expire_date_seconds =
  let (Just p) = G.toPositive 123456
      params = (def :: G.GenKeyParams) {
          G.expireDate = Just $ G.ExpireS p
        }
  in (G.toParamsString params) @?=
      "<GnupgKeyParms format=\"internal\">\n\
      \Key-Type: default\n\
      \Expire-Date: seconds=123456\n\
      \</GnupgKeyParms>\n"

creation_date_seconds :: Assertion
creation_date_seconds =
  let (Just p) = G.toPositive 123456
      params = (def :: G.GenKeyParams) {
          G.creationDate = Just $ G.CreationS p
        }
  in (G.toParamsString params) @?=
      "<GnupgKeyParms format=\"internal\">\n\
      \Key-Type: default\n\
      \Creation-Date: seconds=123456\n\
      \</GnupgKeyParms>\n"

progress_callback :: Assertion
progress_callback = do
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
    ((length $ lines contents) > 0) @? "No lines in progress file")

  -- Cleanup test
  removeDirectoryRecursive tmpDir
  genRet @?= Nothing
  return $ ret

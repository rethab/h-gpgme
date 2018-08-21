{-# LANGUAGE OverloadedStrings #-}
module CtxTest (tests) where

import Control.Monad.Trans.Maybe
import Control.Monad.Trans.Class (lift)
import qualified Data.ByteString as BS
import Data.Maybe (fromMaybe)
import Control.Exception (catch, fromException)
import System.IO.Error (IOError, isUserError)

import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase)
import Test.HUnit

import Crypto.Gpgme
import TestUtil

tests :: [TestTree]
tests = [ testCase "run_action_with_ctx" run_action_with_ctx
        , testCase "set_armor" set_armor
        , testCase "unset_armor" unset_armor
        , testCase "no_set_listing_mode" no_set_listing_mode
        , testCase "set_listing_mode" set_listing_mode
        , testCase "exception_safe" exception_safe
        ]

run_action_with_ctx :: Assertion
run_action_with_ctx = do
    res <- withCtx "test/alice" "C" OpenPGP $ \_ ->
              return "foo" :: IO BS.ByteString
    res @?= "foo"

set_armor :: Assertion
set_armor = do
    let armorPrefix = "-----BEGIN PGP MESSAGE-----"
    enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
              aPubKey <- MaybeT $ getKey bCtx alice_pub_fpr NoSecret
              lift $ setArmor True bCtx
              lift $ encrypt bCtx [aPubKey] NoFlag "plaintext"
    (armorPrefix `BS.isPrefixOf` fromJustAndRight enc) @? ("Armored must start with " ++ show armorPrefix)

unset_armor :: Assertion
unset_armor = do
    let armorPrefix = "-----BEGIN PGP MESSAGE-----"
    enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
              aPubKey <- MaybeT $ getKey bCtx alice_pub_fpr NoSecret
              lift $ setArmor False bCtx
              lift $ encrypt bCtx [aPubKey] NoFlag "plaintext"
    (not $ armorPrefix `BS.isPrefixOf` fromJustAndRight enc) @? ("Binary must not start with " ++ show armorPrefix)

no_set_listing_mode :: Assertion
no_set_listing_mode = do
    sigs <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
              aPubKey <- MaybeT $ getKey bCtx alice_pub_fpr NoSecret
              kuids <- lift $ keyUserIds' aPubKey
              return $ concatMap keyuserSignatures kuids
    let sigs' = fromMaybe [] sigs
    (length sigs' == 0) @? ("There should be no signatures, but there are some")

set_listing_mode :: Assertion
set_listing_mode = do
    sigs <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
              lift $ setKeyListingMode [KeyListingLocal, KeyListingSigs] bCtx
              aPubKey <- MaybeT $ getKey bCtx alice_pub_fpr NoSecret
              kuids <- lift $ keyUserIds' aPubKey
              return $ concatMap keyuserSignatures kuids
    let sigs' = fromMaybe [] sigs
    (length sigs' > 0) @? ("There should be some signatures, but there are non")

-- Ensure that if an exception occurs then the expected exception type is returned so that we know
-- the context was freed
exception_safe :: Assertion
exception_safe = catch
  ( do
    res <- withCtx "test/alice" "C" OpenPGP $ \_ ->
      (ioError $ userError "Busted") >>
      return "foo" :: IO BS.ByteString
    res @?= "foo")
  ( \(HgpgmeException e) -> do
    let mioe = (fromException e) :: Maybe IOError
    maybe (assertFailure $ show mioe) (\ioe -> isUserError ioe @?= True) mioe
  )

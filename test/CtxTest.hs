{-# LANGUAGE OverloadedStrings #-}
module CtxTest (tests) where

import qualified Data.ByteString as BS

import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase)
import Test.HUnit

import Crypto.Gpgme
import TestUtil

tests :: [TestTree]
tests = [ testCase "run_action_with_ctx" run_action_with_ctx
        , testCase "set_armor" set_armor
        , testCase "unset_armor" unset_armor
        ]

run_action_with_ctx :: Assertion
run_action_with_ctx = do
    res <- withCtx "test/alice" "C" OpenPGP $ \_ ->
              return "foo" :: IO BS.ByteString
    res @?= "foo"

set_armor :: Assertion
set_armor = do
    let armorPrefix = "-----BEGIN PGP MESSAGE-----"
    enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx ->
              do Just aPubKey <- getKey bCtx alice_pub_fpr NoSecret
                 setArmor True bCtx
                 encrypt bCtx [aPubKey] NoFlag "plaintext"
    (armorPrefix `BS.isPrefixOf` fromRight enc) @? ("Armored must start with " ++ show armorPrefix)

unset_armor :: Assertion
unset_armor = do
    let armorPrefix = "-----BEGIN PGP MESSAGE-----"
    enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx ->
              do Just aPubKey <- getKey bCtx alice_pub_fpr NoSecret
                 setArmor False bCtx
                 encrypt bCtx [aPubKey] NoFlag "plaintext"
    (not $ armorPrefix `BS.isPrefixOf` fromRight enc) @? ("Binary must not start with " ++ show armorPrefix)

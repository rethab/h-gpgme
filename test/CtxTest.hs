{-# LANGUAGE OverloadedStrings #-}
module CtxTest (tests) where

import Control.Monad.Trans.Maybe
import Control.Monad.Trans.Class (lift)
import qualified Data.ByteString as BS
import Data.Maybe (fromMaybe)
import Control.Exception (catch, fromException)
import System.IO.Error (isUserError)

import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase)
import Test.HUnit

import Crypto.Gpgme
import TestUtil

tests :: [TestTree]
tests = [ testCase "runActionWithCtx" runActionWithCtx
        , testCase "setArmor" setArmor'
        , testCase "unsetArmor" unsetArmor
        , testCase "noSetListingMode" noSetListingMode
        , testCase "setListingMode" setListingMode
        , testCase "exceptionSafe" exceptionSafe
        ]

runActionWithCtx :: Assertion
runActionWithCtx = do
    res <- withCtx "test/alice" "C" OpenPGP $ \_ ->
              return "foo" :: IO BS.ByteString
    res @?= "foo"

setArmor' :: Assertion
setArmor' = do
    let armorPrefix = "-----BEGIN PGP MESSAGE-----"
    enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
              aPubKey <- MaybeT $ getKey bCtx alicePubFpr NoSecret
              lift $ setArmor True bCtx
              lift $ encrypt bCtx [aPubKey] NoFlag "plaintext"
    (armorPrefix `BS.isPrefixOf` fromJustAndRight enc) @? ("Armored must start with " ++ show armorPrefix)

unsetArmor :: Assertion
unsetArmor = do
    let armorPrefix = "-----BEGIN PGP MESSAGE-----"
    enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
              aPubKey <- MaybeT $ getKey bCtx alicePubFpr NoSecret
              lift $ setArmor False bCtx
              lift $ encrypt bCtx [aPubKey] NoFlag "plaintext"
    not (armorPrefix `BS.isPrefixOf` fromJustAndRight enc) @? ("Binary must not start with " ++ show armorPrefix)

noSetListingMode :: Assertion
noSetListingMode = do
    sigs <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
              aPubKey <- MaybeT $ getKey bCtx alicePubFpr NoSecret
              kuids <- lift $ keyUserIds' aPubKey
              return $ concatMap keyuserSignatures kuids
    let sigs' = fromMaybe [] sigs
    null sigs' @? "There should be no signatures, but there are some"

setListingMode :: Assertion
setListingMode = do
    sigs <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
              lift $ setKeyListingMode [KeyListingLocal, KeyListingSigs] bCtx
              aPubKey <- MaybeT $ getKey bCtx alicePubFpr NoSecret
              kuids <- lift $ keyUserIds' aPubKey
              return $ concatMap keyuserSignatures kuids
    let sigs' = fromMaybe [] sigs
    null sigs' @? "There should be some signatures, but there are non"

-- Ensure that if an exception occurs then the expected exception type is returned so that we know
-- the context was freed
exceptionSafe :: Assertion
exceptionSafe = catch
  ( do
    res <- withCtx "test/alice" "C" OpenPGP $ \_ ->
      ioError (userError "Busted") >>
      return "foo" :: IO BS.ByteString
    res @?= "foo")
  ( \(HgpgmeException e) -> do
    let mioe = fromException e :: Maybe IOError
    maybe (assertFailure $ show mioe) (\ioe -> isUserError ioe @?= True) mioe
  )

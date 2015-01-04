{-# LANGUAGE OverloadedStrings #-}
module CryptoTest (tests) where

import Control.Monad (liftM, when)
import Control.Monad.Trans.Maybe
import Data.List (isInfixOf)
import Data.ByteString.Char8 ()
import qualified Data.ByteString as BS
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase)
import Test.Tasty.QuickCheck
import Test.HUnit hiding (assert)
import Test.QuickCheck.Monadic

import Crypto.Gpgme
import TestUtil

tests :: [TestTree]
tests = [ testProperty "bob_encrypt_for_alice_decrypt"
                       $ bob_encrypt_for_alice_decrypt False
        , testProperty "bob_encrypt_sign_for_alice_decrypt_verify"
                       $ bob_encrypt_sign_for_alice_decrypt_verify False

        , testProperty "bob_encrypt_for_alice_decrypt_with_passphrase_cb"
                       $ bob_encrypt_for_alice_decrypt True
        , testProperty "bob_encrypt_sign_for_alice_decrypt_verify_with_passphrase_cb"
                       $ bob_encrypt_sign_for_alice_decrypt_verify True

        , testProperty "bob_encrypt_for_alice_decrypt_short"
                       bob_encrypt_for_alice_decrypt_short
        , testProperty "bob_encrypt_sign_for_alice_decrypt_verify_short"
                       bob_encrypt_sign_for_alice_decrypt_verify_short

        , testCase "decrypt_garbage" decrypt_garbage
        , testCase "encrypt_wrong_key" encrypt_wrong_key
        , testCase "bob_encrypt_symmetrically" bob_encrypt_symmetrically
        ]

hush :: Monad m => m (Either e a) -> MaybeT m a
hush = MaybeT . liftM (either (const Nothing) Just)

withPassphraseCb :: String -> Ctx -> IO ()
withPassphraseCb passphrase ctx = do
    setPassphraseCallback ctx (Just callback)
  where
    callback _ _ _ = return (Just passphrase)

bob_encrypt_for_alice_decrypt :: Bool -> Plain -> Property
bob_encrypt_for_alice_decrypt passphrCb plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encr_and_decr
        assert $ dec == plain
  where encr_and_decr =
            do -- encrypt
               Just enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
                   aPubKey <- MaybeT $ getKey bCtx alice_pub_fpr NoSecret
                   hush $ encrypt bCtx [aPubKey] NoFlag plain

               -- decrypt
               dec <- withCtx "test/alice" "C" OpenPGP $ \aCtx -> do
                   when passphrCb $ withPassphraseCb "alice123" aCtx
                   decrypt aCtx enc

               return $ fromRight dec

bob_encrypt_for_alice_decrypt_short :: Plain -> Property
bob_encrypt_for_alice_decrypt_short plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encr_and_decr
        assert $ dec == plain
  where encr_and_decr =
            do -- encrypt
               enc <- encrypt' "test/bob" alice_pub_fpr plain

               -- decrypt
               dec <- decrypt' "test/alice" (fromRight enc)

               return $ fromRight dec

bob_encrypt_sign_for_alice_decrypt_verify :: Bool -> Plain -> Property
bob_encrypt_sign_for_alice_decrypt_verify passphrCb plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encr_and_decr
        assert $ dec == plain
  where encr_and_decr =
            do -- encrypt
               Just enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
                   aPubKey <- MaybeT $ getKey bCtx alice_pub_fpr NoSecret
                   hush $ encryptSign bCtx [aPubKey] NoFlag plain

               -- decrypt
               dec <- withCtx "test/alice" "C" OpenPGP $ \aCtx -> do
                   when passphrCb $ withPassphraseCb "alice123" aCtx
                   decryptVerify aCtx enc

               return $ fromRight dec

bob_encrypt_sign_for_alice_decrypt_verify_short :: Plain -> Property
bob_encrypt_sign_for_alice_decrypt_verify_short plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encr_and_decr
        assert $ dec == plain
  where encr_and_decr =
            do -- encrypt
               enc <- encryptSign' "test/bob" alice_pub_fpr plain

               -- decrypt
               dec <- decryptVerify' "test/alice" (fromRight enc)

               return $ fromRight dec

encrypt_wrong_key :: Assertion
encrypt_wrong_key = do 
    res <- encrypt' "test/bob" "INEXISTENT" "plaintext"
    assertBool "should fail" (isLeft res)
    let err = fromLeft res
    assertBool "should contain key" ("INEXISTENT" `isInfixOf` err)

decrypt_garbage :: Assertion
decrypt_garbage = do
    val <- withCtx "test/bob" "C" OpenPGP $ \bCtx ->
              decrypt bCtx (BS.pack [1,2,3,4,5,6])
    isLeft val @? "should be left " ++ show val

bob_encrypt_symmetrically :: Assertion
bob_encrypt_symmetrically = do

        -- encrypt
        cipher <- fmap fromRight $
                    withCtx "test/bob" "C" OpenPGP $ \ctx ->
                        encrypt ctx [] NoFlag "plaintext"
        assertBool "must not be plain" (cipher /= "plaintext")

        -- decrypt
        plain <- fmap fromRight $
                    withCtx "test/alice" "C" OpenPGP $ \ctx ->
                        decrypt ctx cipher

        assertEqual "should decrypt to same" "plaintext" plain

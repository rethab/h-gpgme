{-# LANGUAGE OverloadedStrings #-}
module CryptoTest (tests) where

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
                       bob_encrypt_for_alice_decrypt
        , testProperty "bob_encrypt_sign_for_alice_decrypt_verify"
                       bob_encrypt_sign_for_alice_decrypt_verify
        , testProperty "bob_encrypt_for_alice_decrypt_short"
                       bob_encrypt_for_alice_decrypt_short
        , testProperty "bob_encrypt_sign_for_alice_decrypt_verify_short"
                       bob_encrypt_sign_for_alice_decrypt_verify_short

        , testCase "decrypt_garbage" decrypt_garbage
        , testCase "encrypt_wrong_key" encrypt_wrong_key
        , testCase "bob_encrypt_symmetrically" bob_encrypt_symmetrically
        ]

bob_encrypt_for_alice_decrypt :: Plain -> Property
bob_encrypt_for_alice_decrypt plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encr_and_decr
        assert $ dec == plain
  where encr_and_decr =
            do let alice_pub_fpr = "EAACEB8A"

               -- encrypt
               enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx ->
                       withKey bCtx alice_pub_fpr NoSecret $ \aPubKey ->
                           encrypt bCtx [aPubKey] NoFlag plain

               -- decrypt
               dec <- withCtx "test/alice" "C" OpenPGP $ \aCtx ->
                       decrypt aCtx (fromJustAndRight enc)

               return $ fromRight dec

bob_encrypt_for_alice_decrypt_short :: Plain -> Property
bob_encrypt_for_alice_decrypt_short plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encr_and_decr
        assert $ dec == plain
  where encr_and_decr =
            do let alice_pub_fpr = "EAACEB8A"

               -- encrypt
               enc <- encrypt' "test/bob" alice_pub_fpr plain

               -- decrypt
               dec <- decrypt' "test/alice" (fromRight enc)

               return $ fromRight dec

bob_encrypt_sign_for_alice_decrypt_verify :: Plain -> Property
bob_encrypt_sign_for_alice_decrypt_verify plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encr_and_decr
        assert $ dec == plain
  where encr_and_decr =
            do let alice_pub_fpr = "EAACEB8A"

               -- encrypt
               enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx ->
                       withKey bCtx alice_pub_fpr NoSecret $ \aPubKey ->
                           encryptSign bCtx [aPubKey] NoFlag plain

               -- decrypt
               dec <- withCtx "test/alice" "C" OpenPGP $ \aCtx ->
                       decryptVerify aCtx (fromJustAndRight enc)

               return $ fromRight dec

bob_encrypt_sign_for_alice_decrypt_verify_short :: Plain -> Property
bob_encrypt_sign_for_alice_decrypt_verify_short plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encr_and_decr
        assert $ dec == plain
  where encr_and_decr =
            do let alice_pub_fpr = "EAACEB8A"

               -- encrypt
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

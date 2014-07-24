{-# LANGUAGE OverloadedStrings #-}
module CryptoTest (tests) where

import Data.ByteString.Char8 ()
import qualified Data.ByteString as BS
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2
import Test.HUnit hiding (assert)
import Test.QuickCheck.Monadic
import Test.QuickCheck

import Crypto.Gpgme
import TestUtil

tests = [ testProperty "bob_encrypt_for_alice_decrypt"
            bob_encrypt_for_alice_decrypt
        , testProperty "bob_encrypt_sign_for_alice_decrypt_verify"
            bob_encrypt_sign_for_alice_decrypt_verify
        , testCase "decrypt_garbage"
            decrypt_garbage
         , testProperty "bob_encrypt_for_alice_decrypt_short"
             bob_encrypt_for_alice_decrypt_short
         , testProperty "bob_encrypt_sign_for_alice_decrypt_verify_short"
             bob_encrypt_sign_for_alice_decrypt_verify_short

        {- very annoying to run, as passphrase callbacks don't work:
        , testProperty "bob_encrypt_symmetrically" bob_encrypt_symmetrically
        -}
        ]

bob_encrypt_for_alice_decrypt :: Plain -> Property
bob_encrypt_for_alice_decrypt plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encr_and_decr
        assert $ dec == plain
  where encr_and_decr =
            do let alice_pub_fpr = "EAACEB8A"

               -- encrypt
               enc <- withCtx "test/bob" "C" openPGP $ \bCtx ->
                       withKey bCtx alice_pub_fpr noSecret $ \aPubKey ->
                           encrypt bCtx [aPubKey] noFlag plain

               -- decrypt
               dec <- withCtx "test/alice" "C" openPGP $ \aCtx ->
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
               enc <- withCtx "test/bob" "C" openPGP $ \bCtx ->
                       withKey bCtx alice_pub_fpr noSecret $ \aPubKey ->
                           encryptSign bCtx [aPubKey] noFlag plain

               -- decrypt
               dec <- withCtx "test/alice" "C" openPGP $ \aCtx ->
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

-- bob_encrypt_symmetrically plain =
--     not (BS.null plain) ==> monadicIO $ do
--         dec <- run encr_and_decr
--         assert $ dec == plain
--   where encr_and_decr =
--             do let symmetric_key = "foo"
-- 
--                -- encrypt
--                enc <- withPWCtx symmetric_key "test/bob" "C" openPGP $ \bCtx ->
--                            encrypt bCtx [] noFlag plain
-- 
--                -- decrypt
--                dec <- withPWCtx symmetric_key "test/alice" "C" openPGP $ \aCtx ->
--                        decrypt aCtx (fromRight enc)
-- 
--                return $ fromRight dec

decrypt_garbage :: Assertion
decrypt_garbage = do
    val <- withCtx "test/bob" "C" openPGP $ \bCtx ->
              decrypt bCtx (BS.pack [1,2,3,4,5,6])
    isLeft val @? "should be left " ++ show val

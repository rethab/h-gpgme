module CryptoTest (tests) where

import qualified Data.ByteString as BS
import Data.Maybe
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2
import Test.HUnit hiding (assert)
import Test.QuickCheck.Monadic
import Test.QuickCheck

import Crypto.Gpgme
import TestUtil

tests = [ testProperty "bob_encrypt_for_alice_decrypt" bob_encrypt_for_alice_decrypt
        , testProperty "bob_encrypt_symmetrically" bob_encrypt_symmetrically
        , testCase "decrypt_garbage" decrypt_garbage
        ]

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
               dec <- withPWCtx "alice123" "test/alice" "C" openPGP $ \aCtx ->
                       decrypt aCtx (fromJustAndRight enc)

               return $ fromRight dec

bob_encrypt_symmetrically plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encr_and_decr
        assert $ dec == plain
  where encr_and_decr =
            do let symmetric_key = "foo"

               -- encrypt
               enc <- withPWCtx symmetric_key "test/bob" "C" openPGP $ \bCtx ->
                           encrypt bCtx [] noFlag plain

               -- decrypt
               dec <- withPWCtx symmetric_key "test/alice" "C" openPGP $ \aCtx ->
                       decrypt aCtx (fromRight enc)

               return $ fromRight dec

decrypt_garbage = do
    val <- withCtx "test/bob" "C" openPGP $ \bCtx ->
              decrypt bCtx (BS.pack [1,2,3,4,5,6])
    isLeft val @? "should be left " ++ show val

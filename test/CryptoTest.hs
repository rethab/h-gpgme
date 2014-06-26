module CryptoTest (tests) where

import qualified Data.ByteString as BS
import Data.Maybe
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck.Monadic
import Test.QuickCheck

import Crypto.Gpgme
import TestUtil

tests = [ testProperty "bob_encrypt_for_alice_decrypt" bob_encrypt_for_alice_decrypt
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
               dec <- withCtx "test/alice" "C" openPGP $ \aCtx ->
                       decrypt aCtx (fromJustAndRight enc)

               return $ fromRight dec

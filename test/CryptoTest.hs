{-# LANGUAGE OverloadedStrings #-}
module CryptoTest (tests, cbTests) where

import System.IO
import System.IO.Temp
import System.Posix.IO
import Control.Monad (liftM, when)
import Control.Monad.Trans.Maybe
import Control.Monad.IO.Class
import Control.Monad.Catch
import Control.Concurrent
import Data.List (isInfixOf)
import Data.ByteString.Char8 ()
import Data.Maybe ( fromJust )
import qualified Data.ByteString as BS
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase)
import Test.Tasty.QuickCheck
import Test.HUnit hiding (assert)
import Test.QuickCheck.Monadic

import Crypto.Gpgme
import Crypto.Gpgme.Types ( GpgmeError (GpgmeError)
                          , SignMode ( Clear, Detach, Normal )
                          )
import TestUtil

tests :: TestTree
tests = testGroup "crypto"
    [ testProperty "bob_encrypt_for_alice_decrypt_prompt_no_ci"
                   $ bob_encrypt_for_alice_decrypt False
    , testProperty "bob_encrypt_sign_for_alice_decrypt_verify_prompt_no_ci"
                   $ bob_encrypt_sign_for_alice_decrypt_verify False

    , testProperty "bob_encrypt_for_alice_decrypt_short_prompt_no_ci"
                   bob_encrypt_for_alice_decrypt_short
    , testProperty "bob_encrypt_sign_for_alice_decrypt_verify_short_prompt_no_ci"
                   bob_encrypt_sign_for_alice_decrypt_verify_short

    , testCase "decrypt_garbage" decrypt_garbage
    , testCase "encrypt_wrong_key" encrypt_wrong_key
    , testCase "bob_encrypt_symmetrically_prompt_no_ci" bob_encrypt_symmetrically
    , testCase "bob_detach_sign_and_verify_specify_key_prompt_no_ci" bob_detach_sign_and_verify_specify_key_prompt
    , testCase "bob_clear_sign_and_verify_specify_key_prompt_no_ci" bob_clear_sign_and_verify_specify_key_prompt
    , testCase "bob_clear_sign_and_verify_default_key_prompt_no_ci" bob_clear_sign_and_verify_default_key_prompt
    , testCase "bob_normal_sign_and_verify_specify_key_prompt_no_ci" bob_normal_sign_and_verify_specify_key_prompt
    , testCase "bob_normal_sign_and_verify_default_key_prompt_no_ci" bob_normal_sign_and_verify_default_key_prompt
    , testCase "encrypt_file_no_ci" encrypt_file
    , testCase "encrypt_stream_no_ci" encrypt_stream
    ]

cbTests :: IO TestTree
cbTests = do
    supported <- withCtx "test/bob" "C" OpenPGP $ \ctx ->
        return $ isPassphraseCbSupported ctx
    if supported
       then return $ testGroup "passphrase-cb"
                [ testProperty "bob_encrypt_for_alice_decrypt"
                               $ bob_encrypt_for_alice_decrypt True
                , testProperty "bob_encrypt_sign_for_alice_decrypt_verify_with_passphrase_cb_prompt_no_ci"
                               $ bob_encrypt_sign_for_alice_decrypt_verify True
                ]
       else return $ testGroup "passphrase-cb" []

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

bob_detach_sign_and_verify_specify_key_prompt :: Assertion
bob_detach_sign_and_verify_specify_key_prompt = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    key <- getKey ctx bob_pub_fpr NoSecret
    let msgToSign = "Clear text message from bob!!"
    resSign <-sign ctx [(fromJust key)] Detach msgToSign
    verifyDetached ctx (fromRight resSign) msgToSign
  assertBool "Could not verify bob's signature was correct" $ isVerifyDetachValid resVerify

bob_clear_sign_and_verify_specify_key_prompt :: Assertion
bob_clear_sign_and_verify_specify_key_prompt = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    key <- getKey ctx bob_pub_fpr NoSecret
    resSign <- sign ctx [(fromJust key)] Clear "Clear text message from bob specifying signing key"
    verifyPlain ctx (fromRight resSign) ""
  assertBool "Could not verify bob's signature was correct" $ isVerifyValid resVerify

bob_clear_sign_and_verify_default_key_prompt :: Assertion
bob_clear_sign_and_verify_default_key_prompt = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    resSign <- sign ctx [] Clear "Clear text message from bob with default key"
    verifyPlain ctx (fromRight resSign) ""
  assertBool "Could not verify bob's signature was correct" $ isVerifyValid resVerify

bob_normal_sign_and_verify_specify_key_prompt :: Assertion
bob_normal_sign_and_verify_specify_key_prompt = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    key <- getKey ctx bob_pub_fpr NoSecret
    resSign <- sign ctx [(fromJust key)] Normal "Normal text message from bob specifying signing key"
    verify ctx (fromRight resSign)
  assertBool "Could not verify bob's signature was correct" $ isVerifyValid resVerify

bob_normal_sign_and_verify_default_key_prompt :: Assertion
bob_normal_sign_and_verify_default_key_prompt = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    resSign <- sign ctx [] Normal "Normal text message from bob with default key"
    verify ctx (fromRight resSign)
  assertBool "Could not verify bob's signature was correct" $ isVerifyValid resVerify

encrypt_file :: Assertion
encrypt_file =
  withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    withPassphraseCb "bob123" ctx
    withTestTmpFiles $ \pp ph cp ch dp dh -> do
      plainFd <- handleToFd ph
      cipherFd <- handleToFd ch
      decryptedFd <- handleToFd dh

      key <- getKey ctx bob_pub_fpr NoSecret

      -- Add plaintext content
      writeFile pp "Plaintext contents. 1234go!"

      -- Encrypt plaintext
      resEnc <- encryptFd ctx [(fromJust key)] NoFlag plainFd cipherFd
      if (resEnc == Right ())
      then return ()
      else assertFailure $ show resEnc

      -- Recreate the cipher FD because it is closed (or something) from the encrypt command
      cipherHandle' <- openFile cp ReadWriteMode
      cipherFd' <- handleToFd cipherHandle'

      -- Decrypt ciphertext
      resDec <- decryptFd ctx cipherFd' decryptedFd
      if (resDec == Right ())
      then return ()
      else assertFailure $ show resDec

      -- Compare plaintext and decrypted text
      plaintext <- readFile pp
      decryptedtext <- readFile dp
      plaintext @=? decryptedtext

-- Encrypt from FD pipe into a FD file
encrypt_stream :: Assertion
encrypt_stream =
  withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    withPassphraseCb "bob123" ctx
    withTestTmpFiles $ \_ _ cp ch dp dh -> do

      cipherFd <- handleToFd ch
      decryptedFd <- handleToFd dh

      -- Use bob's key
      key <- getKey ctx bob_pub_fpr NoSecret

      -- Create pipe
      (pipeRead, pipeWrite) <- createPipe

      -- Write to pipe
      -- Add plaintext content
      let testString = take (1000) $ repeat '.'
      _ <- forkIO $ do
        threadWaitWrite pipeWrite
        _ <- fdWrite pipeWrite testString
        closeFd pipeWrite

      -- Start encrypting in thread
      _ <- forkIO $ do
        threadWaitRead pipeRead
        _ <- encryptFd ctx [(fromJust key)] NoFlag pipeRead cipherFd
        closeFd pipeRead

      -- Wait a second for threads to finish
      threadDelay (1000 * 1000 * 1)

      -- Check result
      -- Recreate the cipher FD because it is closed (or something) from the encrypt command
      threadWaitRead cipherFd
      ch' <- openFile cp ReadWriteMode
      cipherFd' <- handleToFd ch'

      -- Decrypt ciphertext
      resDec <- decryptFd ctx cipherFd' decryptedFd
      if (resDec == Right ())
      then return ()
      else assertFailure $ show resDec

      -- Compare plaintext and decrypted text
      decryptedtext <-readFile dp
      testString @=? decryptedtext

withTestTmpFiles :: (MonadIO m, MonadMask m)
                 => ( FilePath -> Handle -- Plaintext
                 ->   FilePath -> Handle -- Ciphertext
                 ->   FilePath -> Handle -- Decrypted text
                 ->   m a)
                 -> m a
withTestTmpFiles f =
  withSystemTempFile "plain" $ \pp ph ->
    withSystemTempFile "cipher" $ \cp ch ->
      withSystemTempFile "decrypt" $ \dp dh ->
        f pp ph cp ch dp dh


-- Verify that the signature verification is successful
isVerifyValid :: Either t ([(GpgmeError, [SignatureSummary], t1)], t2) -> Bool
isVerifyValid (Right ((v:[]), _)) = (isVerifyValid' v)
isVerifyValid (Right ((v:vs), t)) = (isVerifyValid' v) && isVerifyValid (Right (vs,t))
isVerifyValid _  = False
isVerifyValid' :: (GpgmeError, [SignatureSummary], t) -> Bool
isVerifyValid' (GpgmeError 0, [Green,Valid], _) = True
isVerifyValid' _ = False

-- Verify that the signature verification is successful for verifyDetach
isVerifyDetachValid :: Either t [(GpgmeError, [SignatureSummary], t1)] -> Bool
isVerifyDetachValid (Right ((v:[]))) = (isVerifyDetachValid' v)
isVerifyDetachValid (Right ((v:vs))) = (isVerifyDetachValid' v) && isVerifyDetachValid (Right vs)
isVerifyDetachValid _  = False
isVerifyDetachValid' :: (GpgmeError, [SignatureSummary], t) -> Bool
isVerifyDetachValid' (GpgmeError 0, [Green,Valid], _) = True
isVerifyDetachValid' _ = False

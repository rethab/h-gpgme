{-# LANGUAGE OverloadedStrings #-}
module CryptoTest (tests, cbTests) where

import System.IO
import System.IO.Temp
import System.Posix.IO
import Control.Monad (when)
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
import Crypto.Gpgme.Types ( GpgmeError (GpgmeError) )
import TestUtil

tests :: TestTree
tests = testGroup "crypto"
    [ testProperty "bobEncryptForAliceDecryptPromptNoCi"
                   $ bobEncryptForAliceDecrypt False
    , testProperty "bobEncryptSignForAliceDecryptVerifyPromptNoCi"
                   $ bobEncryptSignForAliceDecryptVerify False

    , testProperty "bobEncryptForAliceDecryptShortPromptNoCi"
                   bobEncryptForAliceDecryptShort
    , testProperty "bobEncryptSignForAliceDecryptVerifyShortPromptNoCi"
                   bobEncryptSignForAliceDecryptVerifyShort

    , testCase "decryptGarbage" decryptGarbage
    , testCase "encryptWrongKey" encryptWrongKey
    , testCase "bobEncryptSymmetricallyPromptNoCi" bobEncryptSymmetrically
    , testCase "bobDetachSignAndVerifySpecifyKeyPromptNoCi" bobDetachSignAndVerifySpecifyKeyPrompt
    , testCase "bobClearSignAndVerifySpecifyKeyPromptNoCi" bobClearSignAndVerifySpecifyKeyPrompt
    , testCase "bobClearSignAndVerifyDefaultKeyPromptNoCi" bobClearSignAndVerifyDefaultKeyPrompt
    , testCase "bobNormalSignAndVerifySpecifyKeyPromptNoCi" bobNormalSignAndVerifySpecifyKeyPrompt
    , testCase "bobNormalSignAndVerifyDefaultKeyPromptNoCi" bobNormalSignAndVerifyDefaultKeyPrompt
    , testCase "encryptFileNoCi" encryptFile
    , testCase "encryptStreamNoCi" encryptStream
    ]

cbTests :: IO TestTree
cbTests = do
    supported <- withCtx "test/bob" "C" OpenPGP $ \ctx ->
        return $ isPassphraseCbSupported ctx
    if supported
       then return $ testGroup "passphrase-cb"
                [ testProperty "bobEncryptForAliceDecrypt"
                               $ bobEncryptForAliceDecrypt True
                , testProperty "bobEncryptSignForAliceDecryptVerifyWithPassphraseCbPromptNoCi"
                               $ bobEncryptSignForAliceDecryptVerify True
                ]
       else return $ testGroup "passphrase-cb" []

hush :: Monad m => m (Either e a) -> MaybeT m a
hush = MaybeT . fmap (either (const Nothing) Just)

withPassphraseCb :: String -> Ctx -> IO ()
withPassphraseCb passphrase ctx = do
    setPassphraseCallback ctx (Just callback)
  where
    callback _ _ _ = return (Just passphrase)

bobEncryptForAliceDecrypt :: Bool -> Plain -> Property
bobEncryptForAliceDecrypt passphrCb plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encrAndDecr
        assert $ dec == plain
  where encrAndDecr =
            do -- encrypt
               Just enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
                   aPubKey <- MaybeT $ getKey bCtx alicePubFpr NoSecret
                   hush $ encrypt bCtx [aPubKey] NoFlag plain

               -- decrypt
               dec <- withCtx "test/alice" "C" OpenPGP $ \aCtx -> do
                   when passphrCb $ withPassphraseCb "alice123" aCtx
                   decrypt aCtx enc

               return $ fromRight dec

bobEncryptForAliceDecryptShort :: Plain -> Property
bobEncryptForAliceDecryptShort plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encrAndDecr
        assert $ dec == plain
  where encrAndDecr =
            do -- encrypt
               enc <- encrypt' "test/bob" alicePubFpr plain

               -- decrypt
               dec <- decrypt' "test/alice" (fromRight enc)

               return $ fromRight dec

bobEncryptSignForAliceDecryptVerify :: Bool -> Plain -> Property
bobEncryptSignForAliceDecryptVerify passphrCb plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encrAndDecr
        assert $ dec == plain
  where encrAndDecr =
            do -- encrypt
               Just enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
                   aPubKey <- MaybeT $ getKey bCtx alicePubFpr NoSecret
                   hush $ encryptSign bCtx [aPubKey] NoFlag plain

               -- decrypt
               dec <- withCtx "test/alice" "C" OpenPGP $ \aCtx -> do
                   when passphrCb $ withPassphraseCb "alice123" aCtx
                   decryptVerify aCtx enc

               return $ fromRight dec

bobEncryptSignForAliceDecryptVerifyShort :: Plain -> Property
bobEncryptSignForAliceDecryptVerifyShort plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encrAndDecr
        assert $ dec == plain
  where encrAndDecr =
            do -- encrypt
               enc <- encryptSign' "test/bob" alicePubFpr plain

               -- decrypt
               dec <- decryptVerify' "test/alice" (fromRight enc)

               return $ fromRight dec

encryptWrongKey :: Assertion
encryptWrongKey = do
    res <- encrypt' "test/bob" "INEXISTENT" "plaintext"
    assertBool "should fail" (isLeft res)
    let err = fromLeft res
    assertBool "should contain key" ("INEXISTENT" `isInfixOf` err)

decryptGarbage :: Assertion
decryptGarbage = do
    val <- withCtx "test/bob" "C" OpenPGP $ \bCtx ->
              decrypt bCtx (BS.pack [1,2,3,4,5,6])
    isLeft val @? "should be left " ++ show val

bobEncryptSymmetrically :: Assertion
bobEncryptSymmetrically = do

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

bobDetachSignAndVerifySpecifyKeyPrompt :: Assertion
bobDetachSignAndVerifySpecifyKeyPrompt = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    key <- getKey ctx bobPubFpr NoSecret
    let msgToSign = "Clear text message from bob!!"
    resSign <-sign ctx [fromJust key] Detach msgToSign
    verifyDetached ctx (fromRight resSign) msgToSign
  assertBool "Could not verify bob's signature was correct" $ isVerifyDetachValid resVerify

bobClearSignAndVerifySpecifyKeyPrompt :: Assertion
bobClearSignAndVerifySpecifyKeyPrompt = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    key <- getKey ctx bobPubFpr NoSecret
    resSign <- sign ctx [fromJust key] Clear "Clear text message from bob specifying signing key"
    verifyPlain ctx (fromRight resSign) ""
  assertBool "Could not verify bob's signature was correct" $ isVerifyValid resVerify

bobClearSignAndVerifyDefaultKeyPrompt :: Assertion
bobClearSignAndVerifyDefaultKeyPrompt = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    resSign <- sign ctx [] Clear "Clear text message from bob with default key"
    verifyPlain ctx (fromRight resSign) ""
  assertBool "Could not verify bob's signature was correct" $ isVerifyValid resVerify

bobNormalSignAndVerifySpecifyKeyPrompt :: Assertion
bobNormalSignAndVerifySpecifyKeyPrompt = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    key <- getKey ctx bobPubFpr NoSecret
    resSign <- sign ctx [fromJust key] Normal "Normal text message from bob specifying signing key"
    verify ctx (fromRight resSign)
  assertBool "Could not verify bob's signature was correct" $ isVerifyValid resVerify

bobNormalSignAndVerifyDefaultKeyPrompt :: Assertion
bobNormalSignAndVerifyDefaultKeyPrompt = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    resSign <- sign ctx [] Normal "Normal text message from bob with default key"
    verify ctx (fromRight resSign)
  assertBool "Could not verify bob's signature was correct" $ isVerifyValid resVerify

encryptFile :: Assertion
encryptFile =
  withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    withPassphraseCb "bob123" ctx
    withTestTmpFiles $ \pp ph cp ch dp dh -> do
      plainFd <- handleToFd ph
      cipherFd <- handleToFd ch
      decryptedFd <- handleToFd dh

      key <- getKey ctx bobPubFpr NoSecret

      -- Add plaintext content
      writeFile pp "Plaintext contents. 1234go!"

      -- Encrypt plaintext
      resEnc <- encryptFd ctx [fromJust key] NoFlag plainFd cipherFd
      if resEnc == Right ()
      then return ()
      else assertFailure $ show resEnc

      -- Recreate the cipher FD because it is closed (or something) from the encrypt command
      cipherHandle' <- openFile cp ReadWriteMode
      cipherFd' <- handleToFd cipherHandle'

      -- Decrypt ciphertext
      resDec <- decryptFd ctx cipherFd' decryptedFd
      if resDec == Right ()
      then return ()
      else assertFailure $ show resDec

      -- Compare plaintext and decrypted text
      plaintext <- readFile pp
      decryptedtext <- readFile dp
      plaintext @=? decryptedtext

-- Encrypt from FD pipe into a FD file
encryptStream :: Assertion
encryptStream =
  withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    withPassphraseCb "bob123" ctx
    withTestTmpFiles $ \_ _ cp ch dp dh -> do

      cipherFd <- handleToFd ch
      decryptedFd <- handleToFd dh

      -- Use bob's key
      key <- getKey ctx bobPubFpr NoSecret

      -- Create pipe
      (pipeRead, pipeWrite) <- createPipe

      -- Write to pipe
      -- Add plaintext content
      let testString = replicate 1000 '.'
      _ <- forkIO $ do
        threadWaitWrite pipeWrite
        _ <- fdWrite pipeWrite testString
        closeFd pipeWrite

      -- Start encrypting in thread
      _ <- forkIO $ do
        threadWaitRead pipeRead
        _ <- encryptFd ctx [fromJust key] NoFlag pipeRead cipherFd
        closeFd pipeRead

      -- Wait a second for threads to finish
      threadDelay (1000 * 1000)

      -- Check result
      -- Recreate the cipher FD because it is closed (or something) from the encrypt command
      threadWaitRead cipherFd
      ch' <- openFile cp ReadWriteMode
      cipherFd' <- handleToFd ch'

      -- Decrypt ciphertext
      resDec <- decryptFd ctx cipherFd' decryptedFd
      if resDec == Right ()
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
isVerifyValid (Right ([v], _)) = isVerifyValid' v
isVerifyValid (Right (v:vs, t)) = isVerifyValid' v && isVerifyValid (Right (vs,t))
isVerifyValid _  = False
isVerifyValid' :: (GpgmeError, [SignatureSummary], t) -> Bool
isVerifyValid' (GpgmeError 0, [Green,Valid], _) = True
isVerifyValid' _ = False

-- Verify that the signature verification is successful for verifyDetach
isVerifyDetachValid :: Either t [(GpgmeError, [SignatureSummary], t1)] -> Bool
isVerifyDetachValid (Right [v]) = isVerifyDetachValid' v
isVerifyDetachValid (Right ((v:vs))) = isVerifyDetachValid' v && isVerifyDetachValid (Right vs)
isVerifyDetachValid _  = False
isVerifyDetachValid' :: (GpgmeError, [SignatureSummary], t) -> Bool
isVerifyDetachValid' (GpgmeError 0, [Green,Valid], _) = True
isVerifyDetachValid' _ = False

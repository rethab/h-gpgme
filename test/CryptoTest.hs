{-# LANGUAGE OverloadedStrings #-}
module CryptoTest (tests) where

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

-- | Anything that unlocks Alice's or Bob's secret key needs their passphrase.
-- The tests supply it through a passphrase callback, which puts gpgme into
-- loopback pinentry mode, so no test asks a human for anything.
--
-- The exception is 'bobEncryptForAliceDecrypt' @False@: it is deliberately
-- callback-free, to cover the path where the passphrase comes from the
-- gpg-agent's own pinentry. It carries a @NoCi@ marker because it wants a
-- human.
tests :: IO TestTree
tests = do
    cbSupported <- withCtx "test/bob" "C" OpenPGP $ \ctx ->
        return $ isPassphraseCbSupported ctx
    return $ testGroup "crypto" $
        [ testProperty "carolEncryptForCarolDecryptShort"
                       carolEncryptForCarolDecryptShort
        , testProperty "carolEncryptSignForCarolDecryptVerifyShort"
                       carolEncryptSignForCarolDecryptVerifyShort

        , testCase "decryptGarbage" decryptGarbage
        , testCase "encryptWrongKey" encryptWrongKey

        , testProperty "bobEncryptForAliceDecryptPromptNoCi"
                       $ bobEncryptForAliceDecrypt False
        ] ++ if cbSupported then passphraseCbTests else []

-- | Tests that can only run where gpgme supports passphrase callbacks, which
-- rules out the gpg 1.x and 2.0 engines (see 'isPassphraseCbSupported').
passphraseCbTests :: [TestTree]
passphraseCbTests =
    [ testProperty "bobEncryptForAliceDecrypt"
                   $ bobEncryptForAliceDecrypt True
    , testProperty "bobEncryptSignForAliceDecryptVerify"
                   $ bobEncryptSignForAliceDecryptVerify True

    , testCase "bobEncryptSymmetricallyNoCi" bobEncryptSymmetrically
    , testCase "bobDetachSignAndVerifySpecifyKey" bobDetachSignAndVerifySpecifyKey
    , testCase "bobClearSignAndVerifySpecifyKey" bobClearSignAndVerifySpecifyKey
    , testCase "bobClearSignAndVerifyDefaultKey" bobClearSignAndVerifyDefaultKey
    , testCase "bobNormalSignAndVerifySpecifyKey" bobNormalSignAndVerifySpecifyKey
    , testCase "bobNormalSignAndVerifyDefaultKey" bobNormalSignAndVerifyDefaultKey
    , testCase "encryptFile" encryptFile
    , testCase "encryptStream" encryptStream
    ]

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
            do
               Just enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
                   aPubKey <- MaybeT $ getKey bCtx alicePubFpr NoSecret
                   hush $ encrypt bCtx [aPubKey] NoFlag plain

               dec <- withCtx "test/alice" "C" OpenPGP $ \aCtx -> do
                   when passphrCb $ withPassphraseCb "alice123" aCtx
                   decrypt aCtx enc

               return $ fromRight dec

carolEncryptForCarolDecryptShort :: Plain -> Property
carolEncryptForCarolDecryptShort plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encrAndDecr
        assert $ dec == plain
  where encrAndDecr =
            do
               enc <- encrypt' "test/carol" carolPubFpr plain

               dec <- decrypt' "test/carol" (fromRight enc)

               return $ fromRight dec

bobEncryptSignForAliceDecryptVerify :: Bool -> Plain -> Property
bobEncryptSignForAliceDecryptVerify passphrCb plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encrAndDecr
        assert $ dec == plain
  where encrAndDecr =
            do
               Just enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> do
                   -- signing unlocks Bob's secret key, so this side needs the
                   -- passphrase as well
                   when passphrCb $ withPassphraseCb "bob123" bCtx
                   runMaybeT $ do
                       aPubKey <- MaybeT $ getKey bCtx alicePubFpr NoSecret
                       hush $ encryptSign bCtx [aPubKey] NoFlag plain

               dec <- withCtx "test/alice" "C" OpenPGP $ \aCtx -> do
                   when passphrCb $ withPassphraseCb "alice123" aCtx
                   decryptVerify aCtx enc

               return $ fromRight dec

carolEncryptSignForCarolDecryptVerifyShort :: Plain -> Property
carolEncryptSignForCarolDecryptVerifyShort plain =
    not (BS.null plain) ==> monadicIO $ do
        dec <- run encrAndDecr
        assert $ dec == plain
  where encrAndDecr =
            do
               enc <- encryptSign' "test/carol" carolPubFpr plain

               dec <- decryptVerify' "test/carol" (fromRight enc)

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

        cipher <- fmap fromRight $
                    withCtx "test/bob" "C" OpenPGP $ \ctx -> do
                        withPassphraseCb symmetricPassphrase ctx
                        encrypt ctx [] NoFlag "plaintext"
        assertBool "must not be plain" (cipher /= "plaintext")

        plain <- fmap fromRight $
                    withCtx "test/alice" "C" OpenPGP $ \ctx -> do
                        withPassphraseCb symmetricPassphrase ctx
                        decrypt ctx cipher

        assertEqual "should decrypt to same" "plaintext" plain
  where
    -- symmetric encryption is not tied to a key, so any passphrase will do as
    -- long as both sides agree on it
    symmetricPassphrase = "symmetric123"

bobDetachSignAndVerifySpecifyKey :: Assertion
bobDetachSignAndVerifySpecifyKey = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    withPassphraseCb "bob123" ctx
    key <- getKey ctx bobPubFpr NoSecret
    let msgToSign = "Clear text message from bob!!"
    resSign <-sign ctx [fromJust key] Detach msgToSign
    verifyDetached ctx (fromRight resSign) msgToSign
  assertBool "Could not verify bob's signature was correct" $ isVerifyDetachValid resVerify

bobClearSignAndVerifySpecifyKey :: Assertion
bobClearSignAndVerifySpecifyKey = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    withPassphraseCb "bob123" ctx
    key <- getKey ctx bobPubFpr NoSecret
    resSign <- sign ctx [fromJust key] Clear "Clear text message from bob specifying signing key"
    verify ctx (fromRight resSign)
  assertBool "Could not verify bob's signature was correct" $ isVerifyValid resVerify

bobClearSignAndVerifyDefaultKey :: Assertion
bobClearSignAndVerifyDefaultKey = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    withPassphraseCb "bob123" ctx
    resSign <- sign ctx [] Clear "Clear text message from bob with default key"
    verify ctx (fromRight resSign)
  assertBool "Could not verify bob's signature was correct" $ isVerifyValid resVerify

bobNormalSignAndVerifySpecifyKey :: Assertion
bobNormalSignAndVerifySpecifyKey = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    withPassphraseCb "bob123" ctx
    key <- getKey ctx bobPubFpr NoSecret
    resSign <- sign ctx [fromJust key] Normal "Normal text message from bob specifying signing key"
    verify ctx (fromRight resSign)
  assertBool "Could not verify bob's signature was correct" $ isVerifyValid resVerify

bobNormalSignAndVerifyDefaultKey :: Assertion
bobNormalSignAndVerifyDefaultKey = do
  resVerify <- withCtx "test/bob/" "C" OpenPGP $ \ctx -> do
    withPassphraseCb "bob123" ctx
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

      writeFile pp "Plaintext contents. 1234go!"

      resEnc <- encryptFd ctx [fromJust key] NoFlag plainFd cipherFd
      if resEnc == Right ()
      then return ()
      else assertFailure $ show resEnc

      -- Recreate the cipher FD because it is closed (or something) from the encrypt command
      cipherHandle' <- openFile cp ReadWriteMode
      cipherFd' <- handleToFd cipherHandle'

      resDec <- decryptFd ctx cipherFd' decryptedFd
      if resDec == Right ()
      then return ()
      else assertFailure $ show resDec

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

      key <- getKey ctx bobPubFpr NoSecret

      (pipeRead, pipeWrite) <- createPipe

      let testString = replicate 1000 '.'
      _ <- forkIO $ do
        threadWaitWrite pipeWrite
        _ <- fdWrite pipeWrite testString
        closeFd pipeWrite

      _ <- forkIO $ do
        threadWaitRead pipeRead
        _ <- encryptFd ctx [fromJust key] NoFlag pipeRead cipherFd
        closeFd pipeRead

      threadDelay (1000 * 1000)

      -- Recreate the cipher FD because it is closed (or something) from the encrypt command
      threadWaitRead cipherFd
      ch' <- openFile cp ReadWriteMode
      cipherFd' <- handleToFd ch'

      resDec <- decryptFd ctx cipherFd' decryptedFd
      if resDec == Right ()
      then return ()
      else assertFailure $ show resDec

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

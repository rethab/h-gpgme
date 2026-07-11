{-# LANGUAGE OverloadedStrings #-}
module InternalTest (tests) where

import Bindings.Gpgme
import Foreign
import Foreign.C.String (newCString)
import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase)
import Test.HUnit

import Crypto.Gpgme
import Crypto.Gpgme.Internal

tests :: [TestTree]
tests =
    [ testCase "collectSignaturesWithoutVerify" collectSignaturesWithoutVerify
    , testCase "collectFprsWalksList" collectFprsWalksList
    , testCase "verifyGarbageDoesNotCrash" verifyGarbageDoesNotCrash
    ]

-- gpgme_op_verify_result returns NULL when no successful verify ran on
-- the context; this used to segfault (see stackoverflow question 48908274)
collectSignaturesWithoutVerify :: Assertion
collectSignaturesWithoutVerify = do
    _ <- c'gpgme_check_version nullPtr
    ctxPtr <- malloc
    checkError "gpgme_new" =<< c'gpgme_new ctxPtr
    ctx <- peek ctxPtr
    sigs <- collectSignatures' ctx
    c'gpgme_release ctx
    free ctxPtr
    assertEqual "expected no signatures" [] sigs

-- collectFprs used to diverge on any non-empty list because peeking a
-- whole C'_gpgme_invalid_key recurses via its mistyped next field
collectFprsWalksList :: Assertion
collectFprsWalksList = do
    second <- newInvalidKey "BBBB" 2 nullPtr
    first <- newInvalidKey "AAAA" 1 second
    assertEqual "expected both invalid keys" [("AAAA", 1), ("BBBB", 2)] (collectFprs first)
  where
    newInvalidKey fpr reason next = do
        ptr <- mallocBytes (sizeOf (undefined :: C'_gpgme_invalid_key))
        poke (castPtr (p'_gpgme_invalid_key'next ptr)) next
        poke (p'_gpgme_invalid_key'fpr ptr) =<< newCString fpr
        poke (p'_gpgme_invalid_key'reason ptr) reason
        return ptr

verifyGarbageDoesNotCrash :: Assertion
verifyGarbageDoesNotCrash = do
    res <- verify' "test/bob" "this is not a signature"
    case res of
        Left _ -> return ()
        Right r -> assertFailure ("expected verification error, got: " ++ show r)

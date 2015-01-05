module CtxTest (tests) where

import Test.Tasty (TestTree)
import Test.Tasty.HUnit (testCase)
import Test.HUnit

import Crypto.Gpgme

tests :: [TestTree]
tests = [ testCase "run_action_with_ctx" run_action_with_ctx
        -- , testCase "unlock_with_pw" unlock_with_pw
        ]

run_action_with_ctx :: Assertion
run_action_with_ctx = do
    res <- withCtx "test/alice" "C" OpenPGP $ \_ ->
              return "foo"
    res @?= "foo"

-- currently not working:
-- unlock_with_pw =
--     withCtx "test/alice" "C" OpenPGP $ \ctx ->
--         setPassphrase ctx "alice123"

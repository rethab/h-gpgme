module CtxTest (tests) where

import Data.Maybe
import Test.Framework.Providers.HUnit
import Test.HUnit

import Crypto.Gpgme

tests = [ testCase "run_action_with_ctx" run_action_with_ctx
        ]

run_action_with_ctx = do
    res <- withCtx "test/alice" "C" openPGP $ \ctx ->
              return "foo"
    res @?= "foo"

module CtxTest (tests) where

import Data.Maybe
import Test.Framework.Providers.HUnit
import Test.HUnit

import Crypto.Gpgme
import Crypto.Gpgme.Ctx 

tests = [ testCase "run_action_with_ctx" run_action_with_ctx
        -- , testCase "unlock_with_pw" unlock_with_pw
        ]

run_action_with_ctx = do
    res <- withCtx "test/alice" "C" openPGP $ \ctx ->
              return "foo"
    res @?= "foo"

-- currently not working:
-- unlock_with_pw =
--     withCtx "test/alice" "C" openPGP $ \ctx ->
--         setPassphrase ctx "alice123"

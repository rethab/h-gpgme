import Test.Framework (defaultMain, testGroup)

import KeyTest 
import CtxTest 

main = defaultMain
    [ testGroup "key" KeyTest.tests
    , testGroup "ctx" CtxTest.tests
    ]

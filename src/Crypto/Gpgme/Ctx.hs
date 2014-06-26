module Crypto.Gpgme.Ctx (

      newCtx
    , freeCtx
    , withCtx

) where

import Bindings.Gpgme
import Foreign
import Foreign.C.String
import Foreign.C.Types

import Crypto.Gpgme.Types
import Crypto.Gpgme.Internal

newCtx :: String -> String -> Protocol -> IO Ctx
newCtx homedir localeStr (Protocol protocol) =
    do homedirPtr <- newCString homedir

       -- check version: necessary for initialization!!
       version <- c'gpgme_check_version nullPtr >>= peekCString

       -- create context
       ctxPtr <- malloc 
       check_error =<< c'gpgme_new ctxPtr

       ctx <- peek ctxPtr

       -- set locale
       locale <- newCString localeStr
       check_error =<< c'gpgme_set_locale ctx lcCtype locale

       -- set protocol in ctx
       check_error =<< c'gpgme_set_protocol ctx (fromIntegral protocol)

       -- set homedir in ctx
       check_error =<< c'gpgme_ctx_set_engine_info ctx
                            (fromIntegral protocol) nullPtr homedirPtr

       return (Ctx ctxPtr version)
    where lcCtype :: CInt
          lcCtype = 0

freeCtx :: Ctx -> IO ()
freeCtx (Ctx ctxPtr _) =
    do ctx <- peek ctxPtr
       c'gpgme_release ctx
       free ctxPtr

withCtx :: String -> String -> Protocol -> (Ctx -> IO a) -> IO a
withCtx homedir localeStr prot f = do
    ctx <- newCtx homedir localeStr prot
    res <- f ctx
    freeCtx ctx
    return res


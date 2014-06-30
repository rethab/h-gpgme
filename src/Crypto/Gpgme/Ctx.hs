module Crypto.Gpgme.Ctx where

import Bindings.Gpgme
import Foreign
import Foreign.C.String
import Foreign.C.Types
import System.Posix.IO (fdWrite)

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

withPWCtx :: String -> String -> String -> Protocol -> (Ctx -> IO a) -> IO a
withPWCtx pw homedir localeStr prot f = do
    ctx <- newCtx homedir localeStr prot
    putStrLn "Before set passphras"
    setPassphrase ctx pw
    putStrLn "after set passphras"
    res <- f ctx
    freeCtx ctx
    return res

setPassphrase :: Ctx -> String -> IO ()
setPassphrase (Ctx ctxPtr _) passphrase =
    do ctx <- peek ctxPtr
       passcb <- wrap (passphrase_cb passphrase)
       c'gpgme_set_passphrase_cb ctx passcb nullPtr

passphrase_cb :: String -> Ptr () -> CString -> CString -> CInt -> CInt -> IO C'gpgme_error_t
passphrase_cb passphrase _ uid_hint passphrase_info prev_was_bad fd =
    do peekCString uid_hint >>= putStrLn
       peekCString passphrase_info >>= putStrLn
       putStrLn ("Prev was bad: " ++ show prev_was_bad)
       _ <- fdWrite (fromIntegral fd) (passphrase ++ "\n")
       return 0

-- from: http://www.haskell.org/haskellwiki/GHC/Using_the_FFI#Callbacks_into_Haskell_from_foreign_code
foreign import ccall "wrapper"
  wrap :: (Ptr () -> CString -> CString -> CInt -> CInt -> IO C'gpgme_error_t)
          -> IO (FunPtr (Ptr () -> CString -> CString -> CInt -> CInt -> IO C'gpgme_error_t))

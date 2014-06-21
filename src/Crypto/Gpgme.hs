module Crypto.Gpgme (
      -- ctx
      newCtx
    , freeCtx
    , withCtx
    
    -- keys
    , getKey
    , freeKey
    , withKey

    -- encryption
    , encrypt

      -- types
    , Ctx

    , Protocol
    , openPGP

    , InvalidKey

    , IncludeSecret
    , noSecret
    , secret

    , Flag
    , alwaysTrust
    , noFlag

) where

import Bindings.Gpgme
import qualified Data.ByteString as BS
import Foreign
import Foreign.C.String
import Foreign.C.Types

import Crypto.Gpgme.Internal
import Crypto.Gpgme.Types
import Crypto.Gpgme.Key

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

encrypt :: Ctx -> [Key] -> Flag -> BS.ByteString -> IO (Either [InvalidKey] BS.ByteString)
encrypt (Ctx ctxPtr _) recPtrs (Flag flag) plain = do
    -- init buffer with plaintext
    plainBufPtr <- malloc
    BS.useAsCString plain $ \bs -> do
        let copyData = 1 -- gpgme shall copy data, as bytestring will free it
        let plainlen = fromIntegral (BS.length plain)
        ret <- c'gpgme_data_new_from_mem plainBufPtr bs plainlen copyData
        check_error ret
    plainBuf <- peek plainBufPtr

    -- init buffer for result
    resultBufPtr <- malloc
    check_error =<< c'gpgme_data_new resultBufPtr
    resultBuf <- peek resultBufPtr

    -- null terminated array of recipients
    keys <- mapM (peek . unKey) recPtrs
    recArray <- newArray (keys ++ [nullPtr])

    ctx <- peek ctxPtr

    -- encrypt
    check_error =<< c'gpgme_op_encrypt ctx recArray flag plainBuf resultBuf

    -- check whether all keys could be used for encryption
    encResPtr <- c'gpgme_op_encrypt_result ctx
    encRes <- peek encResPtr
    let recPtr = c'_gpgme_op_encrypt_result'invalid_recipients encRes

    if recPtr /= nullPtr
        then return (Left (collectFprs recPtr))
        else return (Right (collectResult resultBuf))

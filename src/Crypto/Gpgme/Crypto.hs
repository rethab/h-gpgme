module Crypto.Gpgme.Crypto (

      encrypt
    , decrypt

) where

import Bindings.Gpgme
import qualified Data.ByteString as BS
import Foreign

import Crypto.Gpgme.Types
import Crypto.Gpgme.Internal

encrypt :: Ctx -> [Key] -> Flag -> BS.ByteString -> IO (Either [InvalidKey] BS.ByteString)
encrypt (Ctx ctxPtr _) recPtrs (Flag flag) plain = do
    -- init buffer with plaintext
    plainBufPtr <- malloc
    BS.useAsCString plain $ \bs -> do
        let copyData = 1 -- gpgme shall copy data, as bytestring will free it
        let plainlen = fromIntegral (BS.length plain)
        ret <- c'gpgme_data_new_from_mem plainBufPtr bs plainlen copyData
        check_error "data_new_from_mem" ret
    plainBuf <- peek plainBufPtr

    -- init buffer for result
    resultBufPtr <- malloc
    check_error "data_new" =<< c'gpgme_data_new resultBufPtr
    resultBuf <- peek resultBufPtr

    -- null terminated array of recipients
    recArray <- if null recPtrs
                    then return nullPtr
                    else do keys <- mapM (peek . unKey) recPtrs
                            newArray (keys ++ [nullPtr])

    ctx <- peek ctxPtr

    -- encrypt
    check_error "op_encrypt" =<< c'gpgme_op_encrypt ctx recArray flag plainBuf resultBuf

    -- check whether all keys could be used for encryption
    encResPtr <- c'gpgme_op_encrypt_result ctx
    encRes <- peek encResPtr
    let recPtr = c'_gpgme_op_encrypt_result'invalid_recipients encRes

    if recPtr /= nullPtr
        then return (Left (collectFprs recPtr))
        else return (Right (collectResult resultBuf))

decrypt :: Ctx -> BS.ByteString -> IO (Either DecryptError BS.ByteString)
decrypt (Ctx ctxPtr _) cipher = do
    -- init buffer with cipher
    cipherBufPtr <- malloc
    BS.useAsCString cipher $ \bs -> do
        let copyData = 1 -- gpgme shall copy data, as bytestring will free it
        let cipherlen = fromIntegral (BS.length cipher)
        ret <- c'gpgme_data_new_from_mem cipherBufPtr bs cipherlen copyData
        check_error "data_new_from_mem" ret
    cipherBuf <- peek cipherBufPtr

    -- init buffer for result
    resultBufPtr <- malloc
    check_error "data_new" =<< c'gpgme_data_new resultBufPtr
    resultBuf <- peek resultBufPtr

    ctx <- peek ctxPtr

    -- decrypt
    errcode <- c'gpgme_op_decrypt ctx cipherBuf resultBuf

    if errcode /= noError
        then return (Left  (toDecryptError errcode))
        else return (Right (collectResult resultBuf))
            -- todo freeying

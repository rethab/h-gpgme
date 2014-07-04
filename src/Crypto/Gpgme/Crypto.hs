module Crypto.Gpgme.Crypto (

      encrypt
    , encryptSign
    , decrypt
    , decryptVerify

) where

import Bindings.Gpgme
import qualified Data.ByteString as BS
import Foreign
import GHC.Ptr

import Crypto.Gpgme.Types
import Crypto.Gpgme.Internal

encrypt :: Ctx -> [Key] -> Flag -> BS.ByteString -> IO (Either [InvalidKey] BS.ByteString)
encrypt = encryptIntern c'gpgme_op_encrypt

encryptSign :: Ctx -> [Key] -> Flag -> BS.ByteString -> IO (Either [InvalidKey] BS.ByteString) 
encryptSign = encryptIntern c'gpgme_op_encrypt_sign

encryptIntern :: (C'gpgme_ctx_t
                    -> GHC.Ptr.Ptr C'gpgme_key_t
                    -> C'gpgme_encrypt_flags_t
                    -> C'gpgme_data_t
                    -> C'gpgme_data_t
                    -> IO C'gpgme_error_t
                  )
                  -> Ctx
                  -> [Key]
                  -> Flag
                  -> BS.ByteString
                  -> IO (Either [InvalidKey] BS.ByteString) 
encryptIntern enc_op (Ctx ctxPtr _) recPtrs (Flag flag) plain = do
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
    check_error "op_encrypt" =<< enc_op ctx recArray flag plainBuf resultBuf
    free plainBufPtr

    -- check whether all keys could be used for encryption
    encResPtr <- c'gpgme_op_encrypt_result ctx
    encRes <- peek encResPtr
    let recPtr = c'_gpgme_op_encrypt_result'invalid_recipients encRes

    let res = if recPtr /= nullPtr
                then Left (collectFprs recPtr)
                else Right (collectResult resultBuf)

    free resultBufPtr

    return res



decrypt :: Ctx -> BS.ByteString -> IO (Either DecryptError BS.ByteString)
decrypt = decryptIntern c'gpgme_op_decrypt

decryptVerify :: Ctx -> BS.ByteString -> IO (Either DecryptError BS.ByteString)
decryptVerify = decryptIntern c'gpgme_op_decrypt_verify


decryptIntern :: (C'gpgme_ctx_t
                    -> C'gpgme_data_t
                    -> C'gpgme_data_t
                    -> IO C'gpgme_error_t
                  )
                  -> Ctx
                  -> BS.ByteString
                  -> IO (Either DecryptError BS.ByteString)
decryptIntern dec_op (Ctx ctxPtr _) cipher = do
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
    errcode <- dec_op ctx cipherBuf resultBuf

    let res = if errcode /= noError
                then Left  (toDecryptError errcode)
                else Right (collectResult resultBuf)

    free cipherBufPtr
    free resultBufPtr

    return res

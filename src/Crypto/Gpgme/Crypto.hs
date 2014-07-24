module Crypto.Gpgme.Crypto (

      encrypt
    , encryptSign
    , encrypt'
    , encryptSign'
    , decrypt
    , decrypt'
    , decryptVerify
    , decryptVerify'

) where

import Bindings.Gpgme
import qualified Data.ByteString as BS
import Foreign
import GHC.Ptr

import Crypto.Gpgme.Ctx
import Crypto.Gpgme.Internal
import Crypto.Gpgme.Key
import Crypto.Gpgme.Types

locale :: String
locale = "C"

-- | Convenience wrapper around 'withCtx' and 'withKey' to
--   encrypt a single plaintext for a single recipient with
--   its homedirectory.
encrypt' :: String -> Fpr -> Plain -> IO (Either String Encrypted)
encrypt' = encryptIntern' encrypt

-- | Convenience wrapper around 'withCtx' and 'withKey' to
--   encrypt and sign a single plaintext for a single recipient
--   with its homedirectory.
encryptSign' :: String -> Fpr -> Plain -> IO (Either String Encrypted)
encryptSign' = encryptIntern' encryptSign

encryptIntern' :: (Ctx -> [Key] -> Flag -> Plain
                        -> IO (Either [InvalidKey] Encrypted)
                    ) -> String -> Fpr -> Plain -> IO (Either String Encrypted)
encryptIntern' encrFun gpgDir recFpr plain =
    withCtx gpgDir locale OpenPGP $ \ctx ->
        do mbRes <- withKey ctx recFpr noSecret $ \pubKey ->
                        encrFun ctx [pubKey] noFlag plain
           return $ mapErr mbRes
  where mapErr Nothing = Left $ "no such key: " ++ show recFpr
        mapErr (Just (Left err))  = Left (show err)
        mapErr (Just (Right res)) = Right res

-- | encrypt for a list of recipients
encrypt :: Ctx -> [Key] -> Flag -> Plain -> IO (Either [InvalidKey] Encrypted)
encrypt = encryptIntern c'gpgme_op_encrypt

-- | encrypt and sign for a list of recipients
encryptSign :: Ctx -> [Key] -> Flag -> Plain -> IO (Either [InvalidKey] Encrypted) 
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
                  -> Plain
                  -> IO (Either [InvalidKey] Encrypted) 
encryptIntern enc_op (Ctx ctxPtr _) recPtrs (Flag flag) plain = do
    -- init buffer with plaintext
    plainBufPtr <- malloc
    BS.useAsCString plain $ \bs -> do
        let copyData = 1 -- gpgme shall copy data, as bytestring will free it
        let plainlen = fromIntegral (BS.length plain)
        ret <- c'gpgme_data_new_from_mem plainBufPtr bs plainlen copyData
        checkError "data_new_from_mem" ret
    plainBuf <- peek plainBufPtr

    -- init buffer for result
    resultBufPtr <- newDataBuffer
    resultBuf <- peek resultBufPtr

    -- null terminated array of recipients
    recArray <- if null recPtrs
                    then return nullPtr
                    else do keys <- mapM (peek . unKey) recPtrs
                            newArray (keys ++ [nullPtr])

    ctx <- peek ctxPtr

    -- encrypt
    checkError "op_encrypt" =<< enc_op ctx recArray flag plainBuf resultBuf
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

-- | Convenience wrapper around 'withCtx' and 'withKey' to
--   decrypt a single ciphertext with its homedirectory.
decrypt' :: String -> Encrypted -> IO (Either DecryptError Plain)
decrypt' = decryptInternal' decrypt

-- | Convenience wrapper around 'withCtx' and 'withKey' to
--   decrypt and verify a single ciphertext with its homedirectory.
decryptVerify' :: String -> Encrypted -> IO (Either DecryptError Plain)
decryptVerify' = decryptInternal' decryptVerify

decryptInternal' :: (Ctx -> Encrypted -> IO (Either DecryptError Plain))
                  -> String
                  -> Encrypted
                  -> IO (Either DecryptError Plain)
decryptInternal' decrFun gpgDir cipher =
    withCtx gpgDir locale OpenPGP $ \ctx ->
        decrFun ctx cipher

-- | Decrypts a ciphertext
decrypt :: Ctx -> Encrypted -> IO (Either DecryptError Plain)
decrypt = decryptIntern c'gpgme_op_decrypt

-- | Decrypts and verifies a ciphertext
decryptVerify :: Ctx -> Encrypted -> IO (Either DecryptError Plain)
decryptVerify = decryptIntern c'gpgme_op_decrypt_verify


decryptIntern :: (C'gpgme_ctx_t
                    -> C'gpgme_data_t
                    -> C'gpgme_data_t
                    -> IO C'gpgme_error_t
                  )
                  -> Ctx
                  -> Encrypted
                  -> IO (Either DecryptError Plain)
decryptIntern dec_op (Ctx ctxPtr _) cipher = do
    -- init buffer with cipher
    cipherBufPtr <- malloc
    BS.useAsCString cipher $ \bs -> do
        let copyData = 1 -- gpgme shall copy data, as bytestring will free it
        let cipherlen = fromIntegral (BS.length cipher)
        ret <- c'gpgme_data_new_from_mem cipherBufPtr bs cipherlen copyData
        checkError "data_new_from_mem" ret
    cipherBuf <- peek cipherBufPtr

    -- init buffer for result
    resultBufPtr <- newDataBuffer
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

newDataBuffer :: IO (Ptr C'gpgme_data_t)
newDataBuffer = do
    resultBufPtr <- malloc
    checkError "data_new" =<< c'gpgme_data_new resultBufPtr
    return resultBufPtr

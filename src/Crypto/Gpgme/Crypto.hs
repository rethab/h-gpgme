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

decrypt :: Ctx -> BS.ByteString -> IO (Either String BS.ByteString)
decrypt = undefined

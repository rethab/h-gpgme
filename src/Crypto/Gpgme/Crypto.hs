module Crypto.Gpgme.Crypto (

      encrypt
    , encryptSign
    , encryptFd
    , encryptSignFd
    , encrypt'
    , encryptSign'
    , decrypt
    , decryptFd
    , decryptVerifyFd
    , decrypt'
    , decryptVerify
    , decryptVerify'
    , verify
    , verify'
    , verifyDetached
    , verifyDetached'
    , verifyPlain
    , verifyPlain'
    , sign

) where

import System.Posix.Types (Fd(Fd))
import Bindings.Gpgme
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Control.Monad.Trans.Except (ExceptT(ExceptT), runExceptT, mapExceptT)
import Foreign
import Foreign.ForeignPtr.Unsafe (unsafeForeignPtrToPtr)
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

orElse :: Monad m => m (Maybe a) -> e -> ExceptT e m a
orElse action err = ExceptT $ maybe (Left err) return `fmap` action

bimapExceptT :: Functor m => (x -> y) -> (a -> b) -> ExceptT x m a -> ExceptT y m b
bimapExceptT f g = mapExceptT (fmap h)
  where
    h (Left  e) = Left  (f e)
    h (Right a) = Right (g a)

encryptIntern' :: (Ctx -> [Key] -> Flag -> Plain
                        -> IO (Either [InvalidKey] Encrypted)
                    ) -> String -> Fpr -> Plain -> IO (Either String Encrypted)
encryptIntern' encrFun gpgDir recFpr plain =
    withCtx gpgDir locale OpenPGP $ \ctx -> runExceptT $
        do pubKey <- getKey ctx recFpr NoSecret `orElse` ("no such key: " ++ show recFpr)
           bimapExceptT show id $ ExceptT $ encrFun ctx [pubKey] NoFlag plain

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
encryptIntern enc_op Ctx {_ctx=ctxPtr} recPtrs flag plain = do
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

    ctx <- peek ctxPtr

    -- encrypt
    withKeyPtrArray recPtrs $ \recArray -> 
        checkError "op_encrypt" =<< enc_op ctx recArray (fromFlag flag)
                                        plainBuf resultBuf
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

-- | Encrypt plaintext
encryptFd :: Ctx -> [Key] -> Flag -> Fd -> Fd -> IO (Either [InvalidKey] ())
encryptFd = encryptFdIntern c'gpgme_op_encrypt

-- | Encrypt and sign plaintext
encryptSignFd :: Ctx -> [Key] -> Flag -> Fd -> Fd -> IO (Either [InvalidKey] ())
encryptSignFd = encryptFdIntern c'gpgme_op_encrypt_sign

encryptFdIntern :: (C'gpgme_ctx_t
                 -> GHC.Ptr.Ptr C'gpgme_key_t
                 -> C'gpgme_encrypt_flags_t
                 -> C'gpgme_data_t
                 -> C'gpgme_data_t
                 -> IO C'gpgme_error_t
               )
               -> Ctx
               -> [Key]
               -> Flag
               -> Fd  -- ^ Plaintext data
               -> Fd  -- ^ Ciphertext data
               -> IO (Either [InvalidKey] ())
encryptFdIntern enc_op Ctx {_ctx=ctxPtr} recPtrs flag (Fd plainCInt) (Fd cipherCInt) = do
  -- Initialize plaintext buffer
  plainBufPtr <- malloc
  _ <- c'gpgme_data_new_from_fd plainBufPtr plainCInt
  plainBuf <- peek plainBufPtr

  -- Initialize ciphertext buffer
  cipherBufPtr <- malloc
  _ <- c'gpgme_data_new_from_fd cipherBufPtr cipherCInt
  cipherBuf <- peek cipherBufPtr

  ctx <- peek ctxPtr

  -- encrypt
  withKeyPtrArray recPtrs $ \recArray ->
      checkError "op_encrypt" =<< enc_op ctx recArray (fromFlag flag)
                                      plainBuf cipherBuf
  free plainBufPtr

  -- check whether all keys could be used for encryption
  encResPtr <- c'gpgme_op_encrypt_result ctx
  encRes <- peek encResPtr
  let recPtr = c'_gpgme_op_encrypt_result'invalid_recipients encRes

  let res = if recPtr /= nullPtr
              then Left (collectFprs recPtr)
              else Right ()

  free cipherBufPtr

  return res

-- | Build a null-terminated array of pointers from a list of 'Key's
withKeyPtrArray :: [Key] -> (Ptr C'gpgme_key_t -> IO a) -> IO a
withKeyPtrArray [] f   = f nullPtr
withKeyPtrArray keys f = do
    arr <- newArray0 nullPtr =<< mapM (peek . unsafeForeignPtrToPtr . unKey) keys
    f arr

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
decryptIntern dec_op Ctx {_ctx=ctxPtr} cipher = do
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

-- | Decrypt a ciphertext
decryptFd :: Ctx -> Fd -> Fd -> IO (Either DecryptError ())
decryptFd = decryptFdIntern c'gpgme_op_decrypt

-- | Decrypt and verify ciphertext
decryptVerifyFd :: Ctx -> Fd -> Fd -> IO (Either DecryptError ())
decryptVerifyFd = decryptFdIntern c'gpgme_op_decrypt_verify

decryptFdIntern :: (C'gpgme_ctx_t
                    -> C'gpgme_data_t
                    -> C'gpgme_data_t
                    -> IO C'gpgme_error_t
                  )
                  -> Ctx
                  -> Fd
                  -> Fd
                  -> IO (Either DecryptError ())
decryptFdIntern dec_op Ctx {_ctx=ctxPtr} (Fd cipherCInt) (Fd plainCInt)= do
  -- Initialize ciphertext buffer
  cipherBufPtr <- malloc
  _ <- c'gpgme_data_new_from_fd cipherBufPtr cipherCInt
  cipherBuf <- peek cipherBufPtr

  -- Initialize plaintext buffer
  plainBufPtr <- malloc
  _ <- c'gpgme_data_new_from_fd plainBufPtr plainCInt
  plainBuf <- peek plainBufPtr

  ctx <- peek ctxPtr

  -- decrypt
  errcode <- dec_op ctx cipherBuf plainBuf

  let res = if errcode /= noError
              then Left  (toDecryptError errcode)
              else Right ()

  free cipherBufPtr
  free plainBufPtr

  return res

-- | Sign plaintext for a list of signers
sign :: Ctx      -- ^ Context to sign
     -> [Key]    -- ^ Keys to used for signing. An empty list will use context's default key.
     -> SignMode -- ^ Signing mode
     -> Plain    -- ^ Plain text to sign
     -> IO (Either [InvalidKey] Plain)
sign = signIntern c'gpgme_op_sign

signIntern :: (    C'gpgme_ctx_t
                -> C'gpgme_data_t
                -> C'gpgme_data_t
                -> C'gpgme_sig_mode_t
                -> IO C'gpgme_error_t
              ) -- ^ c'gpgme_op_sign type signature
              -> Ctx
              -> [Key]
              -> SignMode
              -> Plain
              -> IO (Either [InvalidKey] Encrypted)
signIntern sign_op Ctx {_ctx=ctxPtr} signPtrs mode plain = do
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

    ctx <- peek ctxPtr

    -- add signing keys
    mapM_ ( \kForPtr -> withForeignPtr (unKey kForPtr)
           (\kPtr -> do
             k <- peek kPtr
             c'gpgme_signers_add ctx k
           )
         ) signPtrs

    -- sign
    let modeCode = case mode of
                     Normal -> c'GPGME_SIG_MODE_NORMAL
                     Detach -> c'GPGME_SIG_MODE_DETACH
                     Clear  -> c'GPGME_SIG_MODE_CLEAR

    checkError "op_sign" =<< sign_op ctx plainBuf resultBuf modeCode
    free plainBufPtr

    -- check whether all keys could be used for signingi
    signResPtr <- c'gpgme_op_sign_result ctx
    signRes <- peek signResPtr
    let recPtr = c'_gpgme_op_sign_result'invalid_signers signRes

    let res = if recPtr /= nullPtr
                then Left (collectFprs recPtr)
                else Right (collectResult resultBuf)

    free resultBufPtr

    return res


-- | Verify a payload with a detached signature
verifyDetached :: Ctx           -- ^ GPG context
               -> Signature     -- ^ Detached signature
               -> BS.ByteString -- ^ Signed text
               -> IO (Either GpgmeError VerificationResult)
verifyDetached ctx sig dat = do
    res <- verifyInternal go ctx sig dat
    return $ fmap fst res
    where
        go ctx' sig' dat' = do
            errcode <- c'gpgme_op_verify ctx' sig' dat' 0
            return (errcode, ())

-- | Convenience wrapper around 'withCtx' to
--   verify a single detached signature with its homedirectory.
verifyDetached' :: String        -- ^ GPG context home directory
                -> Signature     -- ^ Detached signature
                -> BS.ByteString -- ^ Signed text
                -> IO (Either GpgmeError VerificationResult)
verifyDetached' gpgDir sig dat =
    withCtx gpgDir locale OpenPGP $ \ctx ->
        verifyDetached ctx sig dat

{-# DEPRECATED verifyPlain "Use verify" #-}
verifyPlain :: Ctx -> Signature -> BS.ByteString -> IO (Either GpgmeError (VerificationResult, BS.ByteString))
verifyPlain c s _ = verify c s
{-# DEPRECATED verifyPlain' "Use verify'" #-}
verifyPlain' :: String -> Signature -> BS.ByteString -> IO (Either GpgmeError (VerificationResult, BS.ByteString))
verifyPlain' str sig _ = verify' str sig

-- | Verify a payload with a plain signature
verify :: Ctx -> Signature -> IO (Either GpgmeError (VerificationResult, BS.ByteString))
verify c s = verifyInternal go c s (C8.pack "")
    where
        go ctx sig _ = do
            -- init buffer for result
            resultBufPtr <- newDataBuffer
            resultBuf <- peek resultBufPtr

            errcode <- c'gpgme_op_verify ctx sig 0 resultBuf

            let res = if errcode /= noError
                        then mempty
                        else collectResult resultBuf

            free resultBufPtr

            return (errcode, res)

-- | Convenience wrapper around 'withCtx' to
--   verify a single plain signature with its homedirectory.
verify' :: String -> Signature -> IO (Either GpgmeError (VerificationResult, BS.ByteString))
verify' gpgDir sig =
    withCtx gpgDir locale OpenPGP $ \ctx ->
        verify ctx sig

verifyInternal :: (    C'gpgme_ctx_t
                    -> C'gpgme_data_t
                    -> C'gpgme_data_t
                    -> IO (C'gpgme_error_t, a)
                  )
                  -> Ctx
                  -> Signature
                  -> BS.ByteString
                  -> IO (Either GpgmeError (VerificationResult, a))
verifyInternal ver_op Ctx {_ctx=ctxPtr} sig dat = do
    -- init buffer with signature
    sigBufPtr <- malloc
    BS.useAsCString sig $ \bs -> do
        let copyData = 1 -- gpgme shall copy data, as bytestring will free it
        let siglen = fromIntegral (BS.length sig)
        ret <- c'gpgme_data_new_from_mem sigBufPtr bs siglen copyData
        checkError "data_new_from_mem" ret
    sigBuf <- peek sigBufPtr

    -- init buffer with data
    datBufPtr <- malloc
    BS.useAsCString dat $ \bs -> do
        let copyData = 1 -- gpgme shall copy data, as bytestring will free it
        let datlen = fromIntegral (BS.length dat)
        ret <- c'gpgme_data_new_from_mem datBufPtr bs datlen copyData
        checkError "data_new_from_mem" ret
    datBuf <- peek datBufPtr

    ctx <- peek ctxPtr

    -- verify
    (errcode, res) <- ver_op ctx sigBuf datBuf

    sigs <- collectSignatures' ctx
    let res' = if errcode /= noError
                then Left  (GpgmeError errcode)
                else Right (sigs, res)

    free sigBufPtr
    free datBufPtr

    return res'

newDataBuffer :: IO (Ptr C'gpgme_data_t)
newDataBuffer = do
    resultBufPtr <- malloc
    checkError "data_new" =<< c'gpgme_data_new resultBufPtr
    return resultBufPtr

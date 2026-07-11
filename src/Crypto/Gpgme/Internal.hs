module Crypto.Gpgme.Internal where

import Bindings.Gpgme
import Control.Monad (unless)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS (createAndTrim)
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Internal as LBS (defaultChunkSize)
import Foreign (castPtr, nullPtr, peek, Ptr, malloc)
import Foreign.C.String (peekCString)
import Foreign.C.Types (CUInt, CInt)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.Gpgme.Types

-- Fields are read via the p' accessors: peeking a whole C'_gpgme_invalid_key
-- diverges because its Storable instance recursively peeks the mistyped
-- @next@ field.
collectFprs :: C'gpgme_invalid_key_t -> [InvalidKey]
collectFprs = unsafePerformIO . go
    where go :: C'gpgme_invalid_key_t -> IO [InvalidKey]
          go ptr | ptr == nullPtr = return []
          go ptr = do
            fprPtr <- peek (p'_gpgme_invalid_key'fpr ptr)
            fpr <- if fprPtr == nullPtr then return "" else peekCString fprPtr
            reason <- fromIntegral `fmap` peek (p'_gpgme_invalid_key'reason ptr)
            next <- peek (castPtr (p'_gpgme_invalid_key'next ptr) :: Ptr C'gpgme_invalid_key_t)
            rest <- go next
            return ((fpr, reason) : rest)

-- | Read the buffer into a ByteString.
--
-- Chunks of Data.ByteString.Lazy.Internal.defaultChunkSize are allocated and
-- copied, until the gpgme_data_readbuffer read returns less than this.
-- Then the list of chunks are copied into a strict ByteString by way of a lazy
-- ByteString.
collectResult :: C'gpgme_data_t -> BS.ByteString
collectResult dat' = unsafePerformIO $ do
    -- make sure we start at the beginning
    _ <- c'gpgme_data_seek dat' 0 seekSet
    chunks <- go dat'
    pure $ LBS.toStrict (LBS.fromChunks chunks)
  where makeChunk :: C'gpgme_data_t -> IO BS.ByteString
        makeChunk dat = BS.createAndTrim chunkSize $ \buf -> do
          -- createAndTrim gives a Ptr Word8 but the gpgme functions wants a Ptr ()
          read_bytes <- c'gpgme_data_read dat (castPtr buf) (fromIntegral chunkSize)
          pure $ fromIntegral read_bytes

        go :: C'gpgme_data_t -> IO [BS.ByteString]
        go dat = do
          bs <- makeChunk dat
          if BS.length bs < chunkSize
          then pure [bs]
          else do
            bss <- go dat
            pure (bs : bss)

        seekSet = 0
        chunkSize = LBS.defaultChunkSize

-- ^ Unsafe IO version of `collectSignatures`. Try to use `collectSignatures'` instead.
collectSignatures :: C'gpgme_ctx_t -> VerificationResult
collectSignatures ctx = unsafePerformIO $ collectSignatures' ctx

-- ^ Return signatures a GPG verify action.
collectSignatures' :: C'gpgme_ctx_t -> IO VerificationResult
collectSignatures' ctx = do
    verify_res <- c'gpgme_op_verify_result ctx
    -- NULL unless the last operation on the context was a successful verify
    if verify_res == nullPtr
        then return []
        else go =<< peek (p'_gpgme_op_verify_result'signatures verify_res)
    where
        go sig | sig == nullPtr = return []
        go sig = do
            status <- peek $ p'_gpgme_signature'status sig
            summary <- peek $ p'_gpgme_signature'summary sig
            fprPtr <- peek (p'_gpgme_signature'fpr sig)
            fpr <- if fprPtr == nullPtr then return BS.empty else BS.packCString fprPtr
            next <- peek $ p'_gpgme_signature'next sig
            xs <- go next
            return $ (GpgmeError status, toSignatureSummaries summary, fpr) : xs

checkError :: String -> C'gpgme_error_t -> IO ()
checkError fun gpgme_err =
    unless (gpgme_err == noError) $
           do errstr <- c'gpgme_strerror gpgme_err
              str <- peekCString errstr
              srcstr <- c'gpgme_strsource gpgme_err
              src <- peekCString srcstr
              error ("Fun: " ++ fun ++
                     ", Error: " ++ str ++
                     ", Source: " ++ show src)

noError :: Num a => a
noError = 0

fromKeyListingMode :: KeyListingMode -> C'gpgme_keylist_mode_t
fromKeyListingMode KeyListingLocal        = c'GPGME_KEYLIST_MODE_LOCAL
fromKeyListingMode KeyListingExtern       = c'GPGME_KEYLIST_MODE_EXTERN
fromKeyListingMode KeyListingSigs         = c'GPGME_KEYLIST_MODE_SIGS
fromKeyListingMode KeyListingSigNotations = c'GPGME_KEYLIST_MODE_SIG_NOTATIONS
fromKeyListingMode KeyListingValidate     = c'GPGME_KEYLIST_MODE_VALIDATE


-- The GPGME_EXPORT_MODE_* values are replicated from gpgme.h:
-- bindings-gpgme 0.1 does not bind these constants and 0.2 only
-- binds the ones known to the gpgme version it was built against.
fromExportMode :: ExportMode -> CUInt
fromExportMode ExportMinimal      = 4   -- GPGME_EXPORT_MODE_MINIMAL
fromExportMode ExportSecret       = 16  -- GPGME_EXPORT_MODE_SECRET
fromExportMode ExportRaw          = 32  -- GPGME_EXPORT_MODE_RAW
fromExportMode ExportPKCS12       = 64  -- GPGME_EXPORT_MODE_PKCS12
fromExportMode ExportSSH          = 256 -- GPGME_EXPORT_MODE_SSH
fromExportMode ExportSecretSubkey = 512 -- GPGME_EXPORT_MODE_SECRET_SUBKEY

fromProtocol :: (Num a) => Protocol -> a
fromProtocol CMS     =  c'GPGME_PROTOCOL_CMS
fromProtocol GPGCONF =  c'GPGME_PROTOCOL_GPGCONF
fromProtocol OpenPGP =  c'GPGME_PROTOCOL_OpenPGP
fromProtocol UNKNOWN =  c'GPGME_PROTOCOL_UNKNOWN

fromSecret :: IncludeSecret -> CInt
fromSecret WithSecret = 1
fromSecret NoSecret   = 0

fromFlag :: Flag -> CUInt
fromFlag AlwaysTrust = c'GPGME_ENCRYPT_ALWAYS_TRUST
fromFlag NoFlag      = 0

toValidity :: C'gpgme_validity_t -> Validity
toValidity n
  | n == c'GPGME_VALIDITY_UNKNOWN   = ValidityUnknown
  | n == c'GPGME_VALIDITY_UNDEFINED = ValidityUndefined
  | n == c'GPGME_VALIDITY_NEVER     = ValidityNever
  | n == c'GPGME_VALIDITY_MARGINAL  = ValidityMarginal
  | n == c'GPGME_VALIDITY_FULL      = ValidityFull
  | n == c'GPGME_VALIDITY_ULTIMATE  = ValidityUltimate
  | otherwise                       = error "validityFromInt: Unrecognized trust validity"

toPubKeyAlgo :: C'gpgme_pubkey_algo_t -> PubKeyAlgo
toPubKeyAlgo n
  | n == c'GPGME_PK_RSA   = Rsa
  | n == c'GPGME_PK_RSA_E = RsaE
  | n == c'GPGME_PK_RSA_S = RsaS
  | n == c'GPGME_PK_ELG_E = ElgE
  | n == c'GPGME_PK_DSA   = Dsa
  | n == c'GPGME_PK_ELG   = Elg
  | otherwise             = error "toPubKeyAlgo: Unrecognized public key algorithm"

newDataBuffer :: IO (Ptr C'gpgme_data_t)
newDataBuffer = do
    resultBufPtr <- malloc
    checkError "data_new" =<< c'gpgme_data_new resultBufPtr
    return resultBufPtr

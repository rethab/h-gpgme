module Crypto.Gpgme.Internal where

import Bindings.Gpgme
import Control.Monad (unless)
import qualified Data.ByteString as BS
import Foreign (allocaBytes, castPtr, nullPtr, peek)
import Foreign.C.String (peekCString)
import Foreign.C.Types (CUInt, CInt)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.Gpgme.Types

collectFprs :: C'gpgme_invalid_key_t -> [InvalidKey]
collectFprs result = unsafePerformIO $ peek result >>= go
    where go :: C'_gpgme_invalid_key -> IO [InvalidKey]
          go invalid = do
            fpr <- peekCString (c'_gpgme_invalid_key'fpr invalid)
            let reason = fromIntegral (c'_gpgme_invalid_key'reason invalid)
            rest <- go (c'_gpgme_invalid_key'next invalid)
            return ((fpr, reason) : rest)

collectResult :: C'gpgme_data_t -> BS.ByteString
collectResult dat' = unsafePerformIO $ do
    -- make sure we start at the beginning
    _ <- c'gpgme_data_seek dat' 0 seekSet
    go dat'
  where go :: C'gpgme_data_t -> IO BS.ByteString
        go dat = allocaBytes 1 $ \buf ->
                    do read_bytes <- c'gpgme_data_read dat buf 1
                       if read_bytes == 1
                          then do byte <- peek (castPtr buf)
                                  rest <- go dat
                                  return (byte `BS.cons` rest)
                          else return BS.empty
        seekSet = 0

-- ^ Unsafe IO version of `collectSignatures`. Try to use `collectSignatures'` instead.
collectSignatures :: C'gpgme_ctx_t -> VerificationResult
collectSignatures ctx = unsafePerformIO $ collectSignatures' ctx

-- ^ Return signatures a GPG verify action.
collectSignatures' :: C'gpgme_ctx_t -> IO VerificationResult
collectSignatures' ctx = do
    verify_res <- c'gpgme_op_verify_result ctx
    sigs <- peek $ p'_gpgme_op_verify_result'signatures verify_res
    go sigs
    where
        go sig | sig == nullPtr = return []
        go sig = do
            status <- peek $ p'_gpgme_signature'status sig
            summary <- peek $ p'_gpgme_signature'summary sig
            fpr <- peek (p'_gpgme_signature'fpr sig) >>= BS.packCString
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

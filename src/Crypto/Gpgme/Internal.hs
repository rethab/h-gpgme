module Crypto.Gpgme.Internal where

import Bindings.Gpgme
import Control.Monad (unless)
import qualified Data.ByteString as BS
import Foreign (allocaBytes, castPtr, peek)
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
fromSecret WithSecret = 0
fromSecret NoSecret   = 1

fromFlag :: Flag -> CUInt
fromFlag AlwaysTrust = c'GPGME_ENCRYPT_ALWAYS_TRUST
fromFlag NoFlag      = 0

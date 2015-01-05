module Crypto.Gpgme.Key (
      getKey
    , listKeys
    , freeKey
    , withKey
    ) where

import Bindings.Gpgme
import qualified Data.ByteString as BS
import Foreign

import Crypto.Gpgme.Types
import Crypto.Gpgme.Internal

-- | Returns a list of known 'Key's from the @context@.
listKeys :: Ctx            -- ^ context to operate in
         -> IncludeSecret  -- ^ whether to include the secrets
         -> IO [Key]
listKeys (Ctx ctxPtr _) secret = do
    peek ctxPtr >>= \ctx ->
        c'gpgme_op_keylist_start ctx nullPtr (fromSecret secret) >>= checkError "listKeys"
    let eof = 16383
        go accum = do
            keyPtr <- malloc
            ret <- peek ctxPtr >>= \ctx ->
                c'gpgme_op_keylist_next ctx keyPtr
            code <- c'gpgme_err_code ret
            case ret of
                _ | ret == noError -> go (Key keyPtr : accum)
                  | code == eof    -> return accum
                  | otherwise      -> checkError "listKeys" ret >> return []
    go []

-- | Returns a 'Key' from the @context@ based on its @fingerprint@.
--   As a 'Key' returned from the function needs to be freed
--   with 'freeKey', the use of 'withKey' is encouraged. Returns
--   Nothing if no 'Key' with this 'Fpr' exists.
getKey :: Ctx           -- ^ context to operate in
       -> Fpr           -- ^ fingerprint
       -> IncludeSecret -- ^ whether to include secrets when searching for the key
       -> IO (Maybe Key)
getKey (Ctx ctxPtr _) fpr secret = do
    keyPtr <- malloc
    ret <- BS.useAsCString fpr $ \cFpr ->
        peek ctxPtr >>= \ctx ->
            c'gpgme_get_key ctx cFpr keyPtr (fromSecret secret)
    if ret == noError
        then return . Just . Key $ keyPtr
        else free keyPtr >> return Nothing

-- | Frees a key previously created with 'getKey'
freeKey :: Key -> IO ()
freeKey (Key keyPtr) = free keyPtr

-- | Conveniently runs the @action@ with the 'Key' associated
--   with the 'Fpr' in the 'Ctx' and frees it afterwards.
--   If no 'Key' with this 'Fpr' exists, Nothing is returned.

withKey :: Ctx           -- ^ context to operate in
        -> Fpr           -- ^ fingerprint
        -> IncludeSecret -- ^ whether to include secrets when searching for the key
        -> (Key -> IO a) -- ^ action to be run with key
        -> IO (Maybe a)
withKey ctx fpr is f = do 
    mbkey <- getKey ctx fpr is
    case mbkey of
        Just key -> do res <- f key
                       freeKey key
                       return (Just res)
        Nothing -> return Nothing



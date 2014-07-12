module Crypto.Gpgme.Key (
      getKey
    , freeKey
    , withKey
    ) where

import Bindings.Gpgme
import qualified Data.ByteString as BS
import Foreign

import Crypto.Gpgme.Types
import Crypto.Gpgme.Internal

-- | Returns a 'Key' from the @context@ based on its @fingerprint@.
--   As a 'Key' returned from the function needs to be freed
--   with 'freeKey', the use of 'withKey' is encouraged. Returns
--   Nothing if no 'Key' with this 'Fpr' exists.
getKey :: Ctx           -- ^ context to operate in
       -> Fpr           -- ^ fingerprint
       -> IncludeSecret -- ^ whether to include secrets when searching for the key
       -> IO (Maybe Key)
getKey (Ctx ctxPtr _) fpr (IncludeSecret is) = do
    keyPtr <- malloc
    ret <- BS.useAsCString fpr $ \cFpr ->
        peek ctxPtr >>= \ctx ->
            c'gpgme_get_key ctx cFpr keyPtr is
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



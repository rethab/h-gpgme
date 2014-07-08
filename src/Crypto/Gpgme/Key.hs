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

getKey :: Ctx -> Fpr -> IncludeSecret -> IO (Maybe Key)
getKey (Ctx ctxPtr _) fpr (IncludeSecret is) = do
    keyPtr <- malloc
    ret <- BS.useAsCString fpr $ \cFpr ->
        peek ctxPtr >>= \ctx ->
            c'gpgme_get_key ctx cFpr keyPtr is
    if ret == noError
        then return . Just . Key $ keyPtr
        else free keyPtr >> return Nothing

freeKey :: Key -> IO ()
freeKey (Key keyPtr) = free keyPtr

withKey :: Ctx -> Fpr -> IncludeSecret -> (Key -> IO a) -> IO (Maybe a)
withKey ctx fpr is f = do 
    mbkey <- getKey ctx fpr is
    case mbkey of
        Just key -> do res <- f key
                       freeKey key
                       return (Just res)
        Nothing -> return Nothing



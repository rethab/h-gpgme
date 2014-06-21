module Crypto.Gpgme.Key (
      getKey
    , freeKey
    , withKey
    ) where

import Bindings.Gpgme
import Foreign
import Foreign.C.String

import Crypto.Gpgme.Types
import Crypto.Gpgme.Internal

getKey :: Ctx -> String -> IncludeSecret -> IO (Maybe Key)
getKey (Ctx ctxPtr _) fprStr (IncludeSecret is) = do
    keyPtr <- malloc
    ret <- withCString fprStr $ \fpr ->
              peek ctxPtr >>= \ctx ->
                 c'gpgme_get_key ctx fpr keyPtr is
    if ret == noError
        then return . Just . Key $ keyPtr
        else free keyPtr >> return Nothing

freeKey :: Key -> IO ()
freeKey (Key keyPtr) = free keyPtr

withKey :: Ctx -> String -> IncludeSecret -> (Key -> IO a) -> IO (Maybe a)
withKey ctx fpr is f = do 
    mbkey <- getKey ctx fpr is
    case mbkey of
        Just key -> do res <- f key
                       freeKey key
                       return (Just res)
        Nothing -> return Nothing



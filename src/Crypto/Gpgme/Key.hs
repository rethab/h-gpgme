module Crypto.Gpgme.Key (
      getKey
    , importKeyFromFile
    , importKeyFromBytes
    , listKeys
    , removeKey
    , searchKeys
      -- * Exporting keys
    , exportKey
    , exportSecretKey
    , exportKeys
    , ExportMode (..)
      -- * Information about keys
    , Validity (..)
    , PubKeyAlgo (..)
    , KeySignature (..)
    , UserId (..)
    , KeyUserId (..)
    , keyUserIds
    , keyUserIds'
    , SubKey (..)
    , keySubKeys
    , keySubKeys'
    ) where

import Bindings.Gpgme
import Control.Monad (when)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC8
import Data.Time.Clock
import Data.Time.Clock.POSIX
import Foreign
import Foreign.C
import System.IO.Unsafe

import Crypto.Gpgme.Types
import Crypto.Gpgme.Internal

-- | Returns a list of all known 'Key's from the @context@.
listKeys :: Ctx            -- ^ context to operate in
         -> IncludeSecret  -- ^ whether to restrict to secret keys
         -> IO [Key]
listKeys ctx secret = listKeys' ctx secret nullPtr

-- | Returns a list of known 'Key's from the @context@ that match a given pattern.
searchKeys :: Ctx            -- ^ context to operate in
           -> IncludeSecret  -- ^ whether to restrict to secret keys
           -> String         -- ^ The pattern to look for; It is typically
                             -- matched against the user ids of a key.
           -> IO [Key]
searchKeys ctx secret pat = BS.useAsCString (BSC8.pack pat) (listKeys' ctx secret)

-- | Internal helper function used by both `listKeys` and `searchKeys`.
listKeys' :: Ctx            -- ^ context to operate in
          -> IncludeSecret  -- ^ whether to restrict to secret keys
          -> CString        -- ^ The pattern to look for; It is typically
                            -- matched against the user ids of a key.
          -> IO [Key]
listKeys' Ctx {_ctx=ctxPtr} secret pat = do
    peek ctxPtr >>= \ctx ->
        c'gpgme_op_keylist_start ctx pat (fromSecret secret) >>= checkError "listKeys"
    let eof = 16383
        go accum = do
            key <- allocKey
            ret <- peek ctxPtr >>= \ctx ->
                withKeyPtr key $ c'gpgme_op_keylist_next ctx
            code <- c'gpgme_err_code ret
            case ret of
                _ | ret == noError -> go (key : accum)
                  | code == eof    -> return accum
                  | otherwise      -> checkError "listKeys" ret >> return []
    go []

-- | Returns a 'Key' from the @context@ based on its @fingerprint@.
--   Returns 'Nothing' if no 'Key' with this 'Fpr' exists.
getKey :: Ctx           -- ^ context to operate in
       -> Fpr           -- ^ fingerprint
       -> IncludeSecret -- ^ whether to look for a secret key
       -> IO (Maybe Key)
getKey Ctx {_ctx=ctxPtr} fpr secret = do
    key <- allocKey
    ret <- BS.useAsCString fpr $ \cFpr ->
        peek ctxPtr >>= \ctx ->
            withKeyPtr key $ \keyPtr ->
                c'gpgme_get_key ctx cFpr keyPtr (fromSecret secret)
    if ret == noError
        then return . Just $ key
        else return Nothing

-- | Import a key from a file, this happens in two steps: populate a
-- @gpgme_data_t@ with the contents of the file, import the @gpgme_data_t@
importKeyFromFile :: Ctx -- ^ context to operate in
                  -> FilePath -- ^ file path to read from
                  -> IO (Maybe GpgmeError)
importKeyFromFile ctx fp =
  importData ctx $ \dataPtr ->
    BS.useAsCString (BSC8.pack fp) $ \cFp ->
      c'gpgme_data_new_from_file dataPtr cFp 1

-- | Import a key from a 'BS.ByteString', this happens in two steps: populate a
-- @gpgme_data_t@ with the contents of the buffer, import the @gpgme_data_t@
importKeyFromBytes :: Ctx -- ^ context to operate in
                   -> BS.ByteString -- ^ buffer to read the key from
                   -> IO (Maybe GpgmeError)
importKeyFromBytes ctx key =
  importData ctx $ \dataPtr ->
    BS.useAsCString key $ \cKey -> do
      -- gpgme must copy the buffer: the import in 'importData' runs after
      -- useAsCString returns, at which point cKey has been freed
      let copyData = 1
      let keylen = fromIntegral (BS.length key)
      c'gpgme_data_new_from_mem dataPtr cKey keylen copyData

-- | Populate a fresh @gpgme_data_t@ using the given action and import it.
-- The action is responsible for filling the buffer and returns the result
-- of doing so.
importData :: Ctx -- ^ context to operate in
           -> (Ptr C'gpgme_data_t -> IO C'gpgme_error_t) -- ^ populate the buffer
           -> IO (Maybe GpgmeError)
importData Ctx {_ctx=ctxPtr} populate = do
  -- the populate action allocates the data object itself, so it only
  -- needs an empty cell; it is initialized to NULL because gpgme
  -- leaves it untouched if populating fails
  dataPtr <- malloc
  poke dataPtr nullData
  ret <- populate dataPtr
  mGpgErr <-
    case ret of
      x | x == noError -> do
        retIn <- do
          ctx <- peek ctxPtr
          dat <- peek dataPtr
          c'gpgme_op_import ctx dat
        pure $ if retIn == noError
          then Nothing
          else Just $ GpgmeError retIn
      err -> pure $ Just $ GpgmeError err
  dat <- peek dataPtr
  when (dat /= nullData) $ c'gpgme_data_release dat
  free dataPtr
  pure mGpgErr
  where
    -- gpgme_data_t is bound as an integral type, so NULL is 0
    nullData = 0 :: C'gpgme_data_t

-- | Export the public key with the given @fingerprint@ from the
--   @context@. Returns an empty 'BS.ByteString' if no key with
--   this 'Fpr' exists.
exportKey :: Ctx -- ^ context to operate in
          -> Fpr -- ^ fingerprint of the key to export
          -> IO (Either GpgmeError BS.ByteString)
exportKey ctx fpr = exportKeys ctx [] [fpr]

-- | Export the secret key with the given @fingerprint@ from the
--   @context@.
--
--   Exporting a protected secret key requires its passphrase, which
--   may be supplied through @setPassphraseCallback@.
exportSecretKey :: Ctx -- ^ context to operate in
                -> Fpr -- ^ fingerprint of the key to export
                -> IO (Either GpgmeError BS.ByteString)
exportSecretKey ctx fpr = exportKeys ctx [ExportSecret] [fpr]

-- | Export all keys matching the given @fingerprints@ from the
--   @context@, or all keys if no fingerprint is given.
--
--   The keys are returned in armored format if armor has been
--   enabled on the @context@ (see @setArmor@) and in binary
--   format otherwise.
exportKeys :: Ctx          -- ^ context to operate in
           -> [ExportMode] -- ^ modes for the export
           -> [Fpr]        -- ^ fingerprints of the keys to export,
                           --   or empty to export all keys
           -> IO (Either GpgmeError BS.ByteString)
exportKeys Ctx {_ctx=ctxPtr} modes fprs = do
    dataPtr <- newDataBuffer
    dat <- peek dataPtr
    ret <- withMany BS.useAsCString fprs $ \cFprs ->
        withArray0 nullPtr cFprs $ \pats -> do
            ctx <- peek ctxPtr
            c'gpgme_op_export_ext ctx pats cMode dat
    result <- if ret == noError
        then do
            -- collectResult is lazy: force the copy while the buffer
            -- it reads from is still alive
            let key = collectResult dat
            key `seq` return (Right key)
        else return (Left (GpgmeError ret))
    c'gpgme_data_release dat
    free dataPtr
    return result
  where
    cMode = foldl (\memo -> (memo .|.) . fromExportMode) 0 modes

-- | Removes the 'Key' from @context@
removeKey :: Ctx                    -- ^ context to operate in
          -> Key                    -- ^ key to delete
          -> RemoveKeyFlags         -- ^ flags for remove operation
          -> IO (Maybe GpgmeError)
removeKey Ctx {_ctx=ctxPtr} key flags = do
  ctx <- peek ctxPtr
  ret <- withKeyPtr key (\keyPtr -> do
    k <- peek keyPtr
    c'gpgme_op_delete_ext ctx k cFlags)
  if ret == 0
    then return Nothing
    else return $ Just $ GpgmeError ret
  where
    cFlags = (if allowSecret flags then 1 else 0) .|. (if force flags then 2 else 0)


-- | A key signature
data KeySignature = KeySig { keysigAlgorithm :: PubKeyAlgo
                           , keysigKeyId     :: String
                           , keysigTimestamp :: Maybe UTCTime
                           , keysigExpires   :: Maybe UTCTime
                           , keysigUserId    :: UserId
                             -- TODO: Notations
                           }

readTime :: CLong -> Maybe UTCTime
readTime (-1) = Nothing
readTime 0    = Nothing
readTime t    = Just $ posixSecondsToUTCTime $ realToFrac t

readKeySignatures :: C'gpgme_key_sig_t -> IO [KeySignature]
readKeySignatures p0 = peekList c'_gpgme_key_sig'next p0 >>= mapM readSig
  where
    readSig sig =
        (KeySig (toPubKeyAlgo $ c'_gpgme_key_sig'pubkey_algo sig)
               <$> peekCString (c'_gpgme_key_sig'keyid sig))
               <*> pure (readTime $ c'_gpgme_key_sig'timestamp sig)
               <*> pure (readTime $ c'_gpgme_key_sig'expires sig)
               <*> signerId
      where
        signerId :: IO UserId
        signerId =
            UserId <$> peekCString (c'_gpgme_key_sig'uid sig)
                   <*> peekCString (c'_gpgme_key_sig'name sig)
                   <*> peekCString (c'_gpgme_key_sig'email sig)
                   <*> peekCString (c'_gpgme_key_sig'comment sig)

-- | A user ID consisting of a name, comment, and email address.
data UserId = UserId { userId         :: String
                     , userName       :: String
                     , userEmail      :: String
                     , userComment    :: String
                     }
            deriving (Ord, Eq, Show)

-- | A user ID
data KeyUserId = KeyUserId { keyuserValidity   :: Validity
                           , keyuserId         :: UserId
                           , keyuserSignatures :: [KeySignature]
                           }

peekList :: Storable a => (a -> Ptr a) -> Ptr a -> IO [a]
peekList nextFunc = go []
  where
    go accum p
      | p == nullPtr  = return accum
      | otherwise     = do v <- peek p
                           go (v : accum) (nextFunc v)

-- | Extract 'KeyUserId's from 'Key'.
keyUserIds' :: Key -> IO [KeyUserId]
keyUserIds' key = withForeignPtr (unKey key) $ \keyPtr -> do
    key' <- peek keyPtr >>= peek
    peekList c'_gpgme_user_id'next (c'_gpgme_key'uids key') >>= mapM readKeyUserId
  where
    readKeyUserId :: C'_gpgme_user_id -> IO KeyUserId
    readKeyUserId uid =
        (KeyUserId (toValidity $ c'_gpgme_user_id'validity uid)
          <$> userId')
          <*> readKeySignatures (c'_gpgme_user_id'signatures uid)
      where
        userId' :: IO UserId
        userId' =
            UserId <$> peekCString (c'_gpgme_user_id'uid uid)
                   <*> peekCString (c'_gpgme_user_id'name uid)
                   <*> peekCString (c'_gpgme_user_id'email uid)
                   <*> peekCString (c'_gpgme_user_id'comment uid)

-- | Extract 'KeyUserId's from 'Key'. Uses 'unsafePerformIO' to bypass @IO@ monad!
-- Use 'keyUserIds' instead if possible.
keyUserIds :: Key -> [KeyUserId]
keyUserIds = unsafePerformIO . keyUserIds'

data SubKey = SubKey { subkeyAlgorithm    :: PubKeyAlgo
                     , subkeyLength       :: Int
                     , subkeyKeyId        :: String
                     , subkeyFpr          :: Fpr
                     , subkeyTimestamp    :: Maybe UTCTime
                     , subkeyExpires      :: Maybe UTCTime
                     , subkeyCardNumber   :: Maybe String
                     }

-- | Extract 'SubKey's from 'Key'.
keySubKeys' :: Key -> IO [SubKey]
keySubKeys' key = withForeignPtr (unKey key) $ \keyPtr -> do
    key' <- peek keyPtr >>= peek
    peekList c'_gpgme_subkey'next (c'_gpgme_key'subkeys key') >>= mapM readSubKey
  where
    readSubKey :: C'_gpgme_subkey -> IO SubKey
    readSubKey sub =
        (SubKey
            (toPubKeyAlgo $ c'_gpgme_subkey'pubkey_algo sub)
            (fromIntegral $ c'_gpgme_subkey'length sub)
            <$> peekCString (c'_gpgme_subkey'keyid sub))
        <*> BS.packCString (c'_gpgme_subkey'fpr sub)
        <*> pure (readTime $ c'_gpgme_subkey'timestamp sub)
        <*> pure (readTime $ c'_gpgme_subkey'expires sub)
        <*> orNull peekCString (c'_gpgme_subkey'card_number sub)

orNull :: (Ptr a -> IO b) -> Ptr a -> IO (Maybe b)
orNull f ptr
  | ptr == nullPtr = return Nothing
  | otherwise      = Just <$> f ptr

-- | Extract 'SubKey's from 'Key'. Uses 'unsafePerformIO' to bypass @IO@ monad!
-- Use 'keySubKeys' instead if possible.
keySubKeys :: Key -> [SubKey]
keySubKeys = unsafePerformIO . keySubKeys'

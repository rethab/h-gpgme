module Crypto.Gpgme.Ctx where

import Bindings.Gpgme
import Foreign
import Foreign.C.String
import Foreign.C.Types

import Crypto.Gpgme.Types
import Crypto.Gpgme.Internal

-- | Creates a new 'Ctx' from a @homedirectory@, a @locale@
--   and a @protocol@. Needs to be freed with 'freeCtx', which
--   is why you are encouraged to use 'withCtx'.
newCtx :: String   -- ^ path to gpg homedirectory
       -> String   -- ^ locale
       -> Protocol -- ^ protocol
       -> IO Ctx
newCtx homedir localeStr protocol =
    do homedirPtr <- newCString homedir

       -- check version: necessary for initialization!!
       version <- c'gpgme_check_version nullPtr >>= peekCString

       -- create context
       ctxPtr <- malloc
       checkError "gpgme_new" =<< c'gpgme_new ctxPtr

       ctx <- peek ctxPtr

       -- set locale
       locale <- newCString localeStr
       checkError "set_locale" =<< c'gpgme_set_locale ctx lcCtype locale

       -- set protocol in ctx
       checkError "set_protocol" =<< c'gpgme_set_protocol ctx
                                        (fromProtocol protocol)

       -- set homedir in ctx
       checkError "set_engine_info" =<< c'gpgme_ctx_set_engine_info ctx
                            (fromProtocol protocol) nullPtr homedirPtr

       return (Ctx ctxPtr version)
    where lcCtype :: CInt
          lcCtype = 0

-- | Free a previously created 'Ctx'
freeCtx :: Ctx -> IO ()
freeCtx (Ctx ctxPtr _) =
    do ctx <- peek ctxPtr
       c'gpgme_release ctx
       free ctxPtr

-- | Runs the action with a new 'Ctx' and frees it afterwards
--
--   See 'newCtx' for a descrption of the parameters.
withCtx :: String        -- ^ path to gpg homedirectory
        -> String        -- ^ locale
        -> Protocol      -- ^ protocol
        -> (Ctx -> IO a) -- ^ action to be run with ctx
        -> IO a
withCtx homedir localeStr prot f = do
    ctx <- newCtx homedir localeStr prot
    res <- f ctx
    freeCtx ctx
    return res

-- | Sets the produced output to be ASCII armored
--
--   Inject between `withCtx' and your 'IO a' like
--
-- >    withCtx homedir locale OpenPGP $ withArmor $ \ctx ->
-- >        withKey ctx fpr NoSecret $ \pubkey ->
-- >            encrypt ctx [pubkey] NoFlag plaintext
withArmor :: (Ctx -> IO a) -> Ctx ->  IO a
withArmor f ctx = do
    cctx <- peek $ _ctx ctx
    c'gpgme_set_armor cctx 1
    f ctx

-- | A callback invoked when the engine requires a passphrase to
-- proceed.
type PassphraseCb =
       String     -- ^ User ID hint
    -> String     -- ^ Passphrase info
    -> Bool       -- ^ @True@ if the previous attempt was bad
    -> IO (Maybe String)

passphraseCb :: PassphraseCb -> IO C'gpgme_passphrase_cb_t
passphraseCb callback = do
    let go _ hint info prev_bad fd = do
            hint' <- peekCString hint
            info' <- peekCString info
            result <- callback hint' info' (prev_bad /= 0)
            case result of
              Just phrase -> withCStringLen phrase $ \(s,len) -> do
                  c'gpgme_io_writen fd (castPtr s) (fromIntegral len)
                  return 0
              Nothing     -> return errCanceled
        errCanceled = 99 -- TODO: Use constant
    mk'gpgme_passphrase_cb_t go

-- | Set the callback invoked when a passphrase is required from the user
setPassphraseCallback :: Ctx -> PassphraseCb -> IO ()
setPassphraseCallback (Ctx ctxPtr _) callback = do
    cb <- passphraseCb callback
    ctx <- peek ctxPtr
    c'gpgme_set_passphrase_cb ctx cb nullPtr

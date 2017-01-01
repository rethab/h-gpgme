module Crypto.Gpgme.Types where

import Bindings.Gpgme
import qualified Data.ByteString as BS
import Data.Maybe(catMaybes)
import Foreign
import qualified Foreign.Concurrent as FC
import Foreign.C.String (peekCString)
import System.IO.Unsafe (unsafePerformIO)
import Control.Exception (SomeException, Exception)

-- | the protocol to be used in the crypto engine
data Protocol =
      CMS
    | GPGCONF
    | OpenPGP
    | UNKNOWN
    deriving (Show, Eq, Ord)

-- | Context to be passed around with operations. Use 'newCtx' or
--   'withCtx' in order to obtain an instance.
data Ctx = Ctx {
      _ctx             :: Ptr C'gpgme_ctx_t -- ^ context
    , _version         :: String            -- ^ GPGME version
    , _protocol        :: Protocol          -- ^ context protocol
    , _engineVersion   :: String            -- ^ engine version
}

-- | Modes for signing with GPG
data SignMode = Normal | Detach | Clear deriving Show

-- | a fingerprint
type Fpr = BS.ByteString

-- | a plaintext
type Plain = BS.ByteString

-- | an ciphertext
type Encrypted = BS.ByteString

-- | a signature
type Signature = BS.ByteString

-- | the summary of a signature status
data SignatureSummary =
      BadPolicy                        -- ^ A policy requirement was not met
    | CrlMissing                       -- ^ The CRL is not available
    | CrlTooOld                        -- ^ Available CRL is too old
    | Green                            -- ^ The signature is good but one might want to display some extra information
    | KeyExpired                       -- ^ The key or one of the certificates has expired
    | KeyMissing                       -- ^ Can’t verify due to a missing key or certificate
    | KeyRevoked                       -- ^ The key or at least one certificate has been revoked
    | Red                              -- ^ The signature is bad
    | SigExpired                       -- ^ The signature has expired
    | SysError                         -- ^ A system error occured
    | UnknownSummary C'gpgme_sigsum_t  -- ^ The summary is something else
    | Valid                            -- ^ The signature is fully valid
    deriving (Show, Eq, Ord)

-- | Translate the gpgme_sigsum_t bit vector to a list of SignatureSummary
toSignatureSummaries :: C'gpgme_sigsum_t -> [SignatureSummary]
toSignatureSummaries x = catMaybes $ map (\(mask, val) -> if mask .&. x == 0 then Nothing else Just val)
    [ (c'GPGME_SIGSUM_BAD_POLICY , BadPolicy)
    , (c'GPGME_SIGSUM_CRL_MISSING, CrlMissing)
    , (c'GPGME_SIGSUM_CRL_TOO_OLD, CrlTooOld)
    , (c'GPGME_SIGSUM_GREEN      , Green)
    , (c'GPGME_SIGSUM_KEY_EXPIRED, KeyExpired)
    , (c'GPGME_SIGSUM_KEY_MISSING, KeyMissing)
    , (c'GPGME_SIGSUM_KEY_REVOKED, KeyRevoked)
    , (c'GPGME_SIGSUM_RED        , Red)
    , (c'GPGME_SIGSUM_SIG_EXPIRED, SigExpired)
    , (c'GPGME_SIGSUM_SYS_ERROR  , SysError)
    , (c'GPGME_SIGSUM_VALID      , Valid)
    ]

type VerificationResult = [(GpgmeError, [SignatureSummary], Fpr)]

-- | The fingerprint and an error code
type InvalidKey = (String, Int)
-- TODO map intot better error code

-- | A key from the context
newtype Key = Key { unKey :: ForeignPtr C'gpgme_key_t }

-- | Allocate a key
allocKey :: IO Key
allocKey = do
    keyPtr <- malloc
    let finalize = do
            peek keyPtr >>= c'gpgme_key_unref
            free keyPtr
    Key `fmap` FC.newForeignPtr keyPtr finalize

-- | Perform an action with the pointer to a 'Key'
withKeyPtr :: Key -> (Ptr C'gpgme_key_t -> IO a) -> IO a
withKeyPtr (Key fPtr) f = withForeignPtr fPtr f

-- | Whether to include secret keys when searching
data IncludeSecret =
      WithSecret -- ^ do not include secret keys
    | NoSecret   -- ^ include secret keys
    deriving (Show, Eq, Ord)

data Flag =
      AlwaysTrust
    | NoFlag
    deriving (Show, Eq, Ord)

-- | A GPGME error.
--
-- Errors in GPGME consist of two parts: a code indicating the nature of the fault,
-- and a source indicating from which subsystem the error originated.
newtype GpgmeError = GpgmeError C'gpgme_error_t
                   deriving (Show, Ord, Eq)

-- | An explanatory string for a GPGME error.
errorString :: GpgmeError -> String
errorString (GpgmeError n) =
    unsafePerformIO $ c'gpgme_strerror n >>= peekCString

-- | An explanatory string describing the source of a GPGME error
sourceString :: GpgmeError -> String
sourceString (GpgmeError n) =
    unsafePerformIO $ c'gpgme_strsource n >>= peekCString

-- | error indicating what went wrong in decryption
data DecryptError =
      NoData              -- ^ no data to decrypt
    | Failed              -- ^ not a valid cipher
    | BadPass             -- ^ passphrase for secret was wrong
    | Unknown GpgmeError  -- ^ something else went wrong
    deriving (Show, Eq, Ord)

toDecryptError :: C'gpgme_error_t -> DecryptError
toDecryptError n =
    case unsafePerformIO $ c'gpgme_err_code n of
        58   -> NoData
        152  -> Failed
        11   -> BadPass
        x    -> Unknown (GpgmeError x)

-- | The validity of a user identity
data Validity =
      ValidityUnknown
    | ValidityUndefined
    | ValidityNever
    | ValidityMarginal
    | ValidityFull
    | ValidityUltimate
    deriving (Show, Ord, Eq)

-- | A public-key encryption algorithm
data PubKeyAlgo =
      Rsa
    | RsaE
    | RsaS
    | ElgE
    | Dsa
    | Elg
    deriving (Show, Ord, Eq)

-- | h-gpgme exception for wrapping exception which occur outside of the control of h-gpgme
newtype HgpgmeException = HgpgmeException SomeException deriving (Show)
instance Exception HgpgmeException

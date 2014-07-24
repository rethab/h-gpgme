module Crypto.Gpgme.Types where

import Bindings.Gpgme
import qualified Data.ByteString as BS
import Foreign

-- | the protocol to be used in the crypto engine
data Protocol =
      CMS
    | GPGCONF
    | OpenPGP
    | UNKNOWN

-- | Context to be passed around with operations. Use 'newCtx' or
--   'withCtx' in order to obtain an instance.
data Ctx = Ctx {
      _ctx :: Ptr C'gpgme_ctx_t
    , _version :: String
}

-- | a fingerprint 
type Fpr = BS.ByteString

-- | a plaintext
type Plain = BS.ByteString

-- | an ciphertext
type Encrypted = BS.ByteString

-- | The fingerprint and an error code
type InvalidKey = (String, Int)
-- TODO map intot better error code

-- | A key from the context
newtype Key = Key { unKey :: Ptr C'gpgme_key_t }

-- | Whether to include secret keys when searching
data IncludeSecret =
      WithSecret -- ^ do not include secret keys
    | NoSecret   -- ^ include secret keys

data Flag =
      AlwaysTrust
    | NoFlag

-- | error indicating what went wrong in decryption
data DecryptError =
      NoData      -- ^ no data to decrypt
    | Failed      -- ^ not a valid cipher
    | BadPass     -- ^ passphrase for secret was wrong
    | Unknown Int -- ^ something else went wrong
    deriving (Eq, Show)

toDecryptError :: C'gpgme_err_code_t -> DecryptError
toDecryptError 58  = NoData
toDecryptError 152 = Failed
toDecryptError 11  = BadPass
toDecryptError x   = Unknown (fromIntegral x)

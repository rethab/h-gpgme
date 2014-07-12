module Crypto.Gpgme.Types where

import Bindings.Gpgme
import qualified Data.ByteString as BS
import Foreign.C.Types (CInt, CUInt)
import Foreign

-- | the protocol to be used in the crypto engine
newtype Protocol = Protocol Int

openPGP :: Protocol 
openPGP = Protocol c'GPGME_PROTOCOL_OpenPGP
-- TODO other protocols

-- | Context to be passed around with operations. Use 'newCtx' or
--   'withCtx' in order to obtain an instance.
data Ctx = Ctx {
      _ctx :: Ptr C'gpgme_ctx_t
    , _version :: String
}

type Fpr = BS.ByteString
type Plain = BS.ByteString
type Encrypted = BS.ByteString

-- | The fingerprint and an error code
type InvalidKey = (String, Int)
-- TODO map intot better error code

-- | A key from the context
newtype Key = Key { unKey :: Ptr C'gpgme_key_t }

-- | Whether to include secret keys when searching
newtype IncludeSecret = IncludeSecret CInt

-- | do not consider secret keys when searching
noSecret :: IncludeSecret
noSecret = IncludeSecret 0

-- | consider secret keys when searching
secret :: IncludeSecret
secret = IncludeSecret 1

newtype Flag = Flag CUInt

alwaysTrust :: Flag
alwaysTrust = Flag c'GPGME_ENCRYPT_ALWAYS_TRUST

noFlag :: Flag
noFlag = Flag 0

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

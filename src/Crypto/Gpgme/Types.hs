module Crypto.Gpgme.Types where

import Bindings.Gpgme
import Foreign.C.Types (CInt, CUInt)
import Foreign

newtype Protocol = Protocol Int

openPGP :: Protocol 
openPGP = Protocol c'GPGME_PROTOCOL_OpenPGP
-- TODO other protocols

data Ctx = Ctx {
      _ctx :: Ptr C'gpgme_ctx_t
    , _version :: String
}

-- fingerprint, reason
type InvalidKey = (String, Int)
-- TODO map intot better error code

newtype Key = Key { unKey :: Ptr C'gpgme_key_t }

newtype IncludeSecret = IncludeSecret CInt

noSecret :: IncludeSecret
noSecret = IncludeSecret 0

secret :: IncludeSecret
secret = IncludeSecret 1

newtype Flag = Flag CUInt

alwaysTrust :: Flag
alwaysTrust = Flag c'GPGME_ENCRYPT_ALWAYS_TRUST

noFlag :: Flag
noFlag = Flag 0

data DecryptError =
      NoData  -- no data to decrypt
    | Failed  -- not a valid cipher
    | BadPass -- passphrase for secret was wrong
    | Unknown Int -- something else went wrong
    deriving (Eq, Show)

toDecryptError :: C'gpgme_err_code_t -> DecryptError
toDecryptError 58  = NoData
toDecryptError 152 = Failed
toDecryptError 11  = BadPass
toDecryptError x   = Unknown (fromIntegral x)

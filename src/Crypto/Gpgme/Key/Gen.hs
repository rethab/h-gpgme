{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Crypto.Gpgme.Key.Gen
License     : Public Domain

Maintainer  : daveparrish@tutanota.com
Stability   : experimental
Portability : untested

Key generation for h-gpgme.

It is suggested to import as qualified. For example:

> import qualified  Crypto.Gpgme.Key.Gen as G
-}

module Crypto.Gpgme.Key.Gen (
    -- * Usage
      genKey

    -- * Parameters
    , GenKeyParams (..)
    -- ** BitSize
    , BitSize
    , Crypto.Gpgme.Key.Gen.bitSize
    -- ** UsageList
    , UsageList (..)
    , Encrypt (..)
    , Sign (..)
    , Auth (..)
    -- ** ExpireDate
    , ExpireDate (..)
    -- ** CreationDate
    , CreationDate (..)
    -- * Other
    , Positive (unPositive)
    , toPositive
    , toParamsString
    ) where

import            Crypto.Gpgme.Types
import            Crypto.Gpgme.Internal

import qualified  Data.ByteString        as BS
import qualified  Data.ByteString.Char8  as BSC8
import            Text.Email.Validate
import            Data.Monoid ((<>))
import            Foreign                as F
import            Bindings.Gpgme
import            Data.Time.Clock
import            Data.Time.Format
import            Data.Default

-- | Key generation parameters.
--
-- See: https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
data GenKeyParams = GenKeyParams {
      keyType       :: Maybe PubKeyAlgo
    , keyLength     :: Maybe BitSize
    , keyGrip       :: BS.ByteString
    , keyUsage      :: Maybe UsageList
    , subkeyType    :: Maybe PubKeyAlgo
    , subkeyLength  :: Maybe BitSize
    , passphrase    :: BS.ByteString
    , nameReal      :: BS.ByteString
    , nameComment   :: BS.ByteString
    , nameEmail     :: Maybe EmailAddress
    , expireDate    :: Maybe ExpireDate
    , creationDate  :: Maybe CreationDate
    , preferences   :: BS.ByteString
    , revoker       :: BS.ByteString
    , keyserver     :: BS.ByteString
    , handle        :: BS.ByteString
    , rawParams     :: BS.ByteString  -- ^ Add custom XML
    }

-- | Default parameters
--
-- Intended to be used to build custom paramemters.
--
-- > params = (def :: GenKeyParams) { keyType = Just Dsa }
--
-- See tests for working example of all parameters in use.
instance Default GenKeyParams where
  def = GenKeyParams Nothing Nothing "" Nothing Nothing Nothing "" "" ""
    Nothing Nothing Nothing "" "" "" "" ""

-- | Key-Length parameter
data BitSize = BitSize Int

-- | Bit size constrained to 1024-4096 bits
bitSize :: Int -> Either String BitSize
bitSize x
  | x < 1024  = Left "BitSize must be greater than 1024"
  | x > 4096  = Left "BitSize must be less than 4096"
  | otherwise = Right $ BitSize x

-- Key-Usage types
data Encrypt = Encrypt
data Sign    = Sign
data Auth    = Auth
data UsageList = UsageList {
      encrypt  :: Maybe Encrypt
    , sign     :: Maybe Sign
    , auth     :: Maybe Auth
    }

-- | Default UsageList
--
-- Intended to be used to build custom UsageList parameter
--
-- > usageListParam = (def :: UsageList) (Just Encrypt)
--
-- See tests for working example of all parameters in use.
instance Default UsageList where
  def = UsageList Nothing Nothing Nothing

-- | Expire-Date parameter
--
-- Beware, 'genKey' will not check that ExpireDate is after
-- CreationDate of generated key.
data ExpireDate =
  ExpireT UTCTime | ExpireD Positive | ExpireW Positive |
  ExpireM Positive | ExpireY Positive | ExpireS Positive
-- TODO: Constrain ExpireDate to something that is valid.
--       No ISODate before today or creation date.

-- | Creation-Date parameter
data CreationDate = CreationT UTCTime
                  | CreationS Positive  -- ^ Seconds since epoch

-- | Only a positive Int
data Positive = Positive { unPositive :: Int }
-- | Create a Positive type as long as the Int is greater than @-1@
toPositive :: Int -> Maybe Positive
toPositive n = if (n < 0) then Nothing else Just (Positive n)

-- | Generate a GPG key
genKey :: Ctx           -- ^ context to operate in
       -> GenKeyParams  -- ^ parameters to use for generating key
       -> IO (Maybe GpgmeError)
genKey (Ctx {_ctx=ctxPtr}) params = do
  ret <- F.peek ctxPtr >>= \ctx -> do
    res <- BS.useAsCString (toParamsString params) $ \p -> do
      let nullGpgmeData = 0  -- Using 0 as NULL for gpgme_data_t
      c'gpgme_op_genkey ctx p nullGpgmeData nullGpgmeData
    return res
  if ret == noError
    then return Nothing
    else return . Just $ GpgmeError ret

-- | Used by 'genKey' generate a XML string for GPG
toParamsString :: GenKeyParams -> BS.ByteString
toParamsString params = (BSC8.unlines . filter ((/=)""))
    [ "<GnupgKeyParms format=\"internal\">"
    , "Key-Type: " <> (maybe "default" keyTypeToString $ keyType params)
    , maybeLine "Key-Length: " keyLengthToString $ keyLength params
    , addLabel "Key-Grip: " $ keyGrip params
    , maybeLine "Key-Usage: " keyUsageListToString $ keyUsage params
    , maybeLine "Subkey-Type: " keyTypeToString $ subkeyType params
    , maybeLine "Subkey-Length: " keyLengthToString $ subkeyLength params
    , addLabel "Passphrase: " $ passphrase params
    , addLabel "Name-Real: " $ nameReal params
    , addLabel "Name-Comment: " $ nameComment params
    , maybeLine "Name-Email: " toByteString $ nameEmail params
    , maybeLine "Expire-Date: " expireDateToString $ expireDate params
    , maybeLine "Creation-Date: " creationDateToString $ creationDate params
    , addLabel "Preferences: " $ preferences params
    , addLabel "Revoker: " $ revoker params
    , addLabel "Keyserver: " $ keyserver params
    , addLabel "Handle: " $ handle params
    -- Allow for additional parameters as a raw ByteString
    , rawParams params
    , "</GnupgKeyParms>"
    ]
  where
    maybeLine :: BS.ByteString -> (a -> BS.ByteString) -> Maybe a -> BS.ByteString
    maybeLine h f p = addLabel h $ maybe "" f p
    -- Add label if not an empty string
    addLabel :: BS.ByteString -> BS.ByteString -> BS.ByteString
    addLabel _ "" = ""
    addLabel h s  = h <> s
    keyTypeToString :: PubKeyAlgo -> BS.ByteString
    keyTypeToString Rsa   = "RSA"
    keyTypeToString RsaE  = "RSA-E"
    keyTypeToString RsaS  = "RSA-S"
    keyTypeToString ElgE  = "ELG-E"
    keyTypeToString Dsa   = "DSA"
    keyTypeToString Elg   = "ELG"
    keyLengthToString :: BitSize -> BS.ByteString
    keyLengthToString (BitSize i) = BSC8.pack $ show i
    keyUsageListToString :: UsageList -> BS.ByteString
    keyUsageListToString (UsageList e s a) =
      let eStr = maybe (""::BS.ByteString) (const "encrypt") e
          sStr = maybe (""::BS.ByteString) (const "sign") s
          aStr = maybe (""::BS.ByteString) (const "auth") a
      in (BSC8.intercalate "," . filter ((/=) "" )) [eStr, sStr, aStr]
    expireDateToString :: ExpireDate -> BS.ByteString
    expireDateToString (ExpireD p) = BSC8.pack $ ((show $ unPositive p) ++ "d")
    expireDateToString (ExpireW p) = BSC8.pack $ ((show $ unPositive p) ++ "w")
    expireDateToString (ExpireM p) = BSC8.pack $ ((show $ unPositive p) ++ "m")
    expireDateToString (ExpireY p) = BSC8.pack $ ((show $ unPositive p) ++ "y")
    expireDateToString (ExpireS p) =
      BSC8.pack $ ("seconds=" ++ (show $ unPositive p))
    expireDateToString (ExpireT t) =
      BSC8.pack $ formatTime defaultTimeLocale "%Y%m%dT%H%M%S" t
    creationDateToString :: CreationDate -> BS.ByteString
    creationDateToString (CreationS p) =
      BSC8.pack $ ("seconds=" ++ (show $ unPositive p))
    creationDateToString (CreationT t) =
      BSC8.pack $ formatTime defaultTimeLocale "%Y%m%dT%H%M%S" t

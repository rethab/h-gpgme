
-- |
-- Module      : Crypto.Gpgme
-- Copyright   : (c) Reto Hablützel 2015
-- License     : MIT
--
-- Maintainer  : rethab@rethab.ch
-- Stability   : experimental
-- Portability : untested
--
-- High Level Binding for GnuPG Made Easy (gpgme)
-- 
-- Most of these functions are a one-to-one translation
-- from GnuPG API with some Haskell idiomatics to make
-- the API more convenient.
--
-- See the GnuPG manual for more information: <https://www.gnupg.org/documentation/manuals/gpgme.pdf>
--
--
-- == Example (from the tests):
--
-- >let alice_pub_fpr = "EAACEB8A"                                      
-- >                                                                    
-- >Just enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
-- >        aPubKey <- MaybeT $ getKey bCtx alice_pub_fpr NoSecret      
-- >        fromRight $ encrypt bCtx [aPubKey] NoFlag plain             
-- >                                                                    
-- >-- decrypt                                                          
-- >dec <- withCtx "test/alice" "C" OpenPGP $ \aCtx ->                  
-- >        decrypt aCtx enc                                            
-- >
--

module Crypto.Gpgme (
      -- * Context
      Ctx
    , newCtx
    , freeCtx
    , withCtx
    , setArmor
      -- ** Passphrase callbacks
    , isPassphraseCbSupported
    , PassphraseCb
    , setPassphraseCallback

    -- currently not exported as it does not work as expected:
    -- , withPWCtx
    
    -- * Keys
    , Key
    , getKey
    , listKeys
    -- * Information about keys
    , Validity (..)
    , PubKeyAlgo (..)
    , KeySignature (..)
    , UserId (..)
    , KeyUserId (..)
    , keyUserIds
    , SubKey (..)
    , keySubKeys

    -- * Encryption
    , encrypt
    , encryptSign
    , encrypt'
    , encryptSign'
    , decrypt
    , decrypt'
    , decryptVerify
    , decryptVerify'

    -- * Error handling
    , GpgmeError
    , errorString
    , sourceString

    -- * Other Types
    , Fpr
    , Encrypted
    , Plain

    , Protocol(..)

    , InvalidKey

    , IncludeSecret(..)

    , Flag(..)

    , DecryptError(..)

) where


import Crypto.Gpgme.Ctx
import Crypto.Gpgme.Crypto
import Crypto.Gpgme.Types
import Crypto.Gpgme.Key

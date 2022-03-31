[![Hackage](https://img.shields.io/hackage/v/h-gpgme.svg)](https://hackage.haskell.org/package/h-gpgme) 
[![CI](https://github.com/rethab/h-gpgme/actions/workflows/ci.yml/badge.svg)](https://github.com/rethab/h-gpgme/actions/workflows/ci.yml)
![MIT License](https://img.shields.io/github/license/rethab/h-gpgme?label=license)


h-gpgme: High Level Haskell Bindings for GnuPG Made Easy
========================================================

## Examples

```haskell
let alice_pub_fpr = "EAACEB8A"

-- encrypt
Just enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
        aPubKey <- MaybeT $ getKey bCtx alice_pub_fpr NoSecret
        fromRight $ encrypt bCtx [aPubKey] NoFlag plain

-- decrypt
dec <- withCtx "test/alice" "C" OpenPGP $ \aCtx ->
        decrypt aCtx enc
```

See the test folder for more examples

[Changelog](CHANGELOG.markdown)

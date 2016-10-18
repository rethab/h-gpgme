[![Build Status](https://travis-ci.org/dmp1ce/h-gpgme.svg?branch=master)](https://travis-ci.org/dmp1ce/h-gpgme)

h-gpgme: High Level Haskell Bindings for GnuPG Made Easy
========================================================

## Examples

```haskell
let alice_pub_fpr = "EAACEB8A"

Just enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> runMaybeT $ do
        aPubKey <- MaybeT $ getKey bCtx alice_pub_fpr NoSecret
        fromRight $ encrypt bCtx [aPubKey] NoFlag plain

-- decrypt
dec <- withCtx "test/alice" "C" OpenPGP $ \aCtx ->
        decrypt aCtx enc
```

See the test folder for more examples

[Changelog](CHANGELOG.md)

h-gpgme: High Level Haskell Bindings for GnuPG Made Easy
========================================================

Examples
--------

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

Changelog
---------

- 0.3.0.0 (WIP)
 - Added listKeys (thanks bgamari)
 - Replaced withArmor with setArmor
 - Removed withKey, manual freeing is no longer required so you can use getKey (thanks bgamari)

- 0.2.0.0
 - Added withArmor for ASCII-armored output (thanks yaccz)

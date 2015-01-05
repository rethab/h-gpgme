h-gpgme: High Level Haskell Bindings for GnuPG Made Easy
========================================================

Examples
--------

```haskell
let alice_pub_fpr = "EAACEB8A"

-- encrypt
enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx ->
         withKey bCtx alice_pub_fpr NoSecret $ \aPubKey ->
            encrypt bCtx [aPubKey] NoFlag plain

-- decrypt
dec <- withCtx "alice123" "test/alice" "C" OpenPGP $ \aCtx ->
         decrypt aCtx (fromJustAndRight enc)
```

See the test folder for more examples

Changelog
---------

- 0.2.0.0
 - Added withArmor for ASCII-armored output (thanks yaccz)

- 0.3.0.0 (WIP)
 - Added listKeys (thanks bgamari)
 - Added setArmor
 - withArmor is deprecated

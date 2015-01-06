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

## Changelog


### 0.3.0.0
- Added listKeys (thanks bgamari)
- Replaced withArmor with setArmor
- Removed withKey, manual freeing is no longer required so you can use getKey (thanks bgamari)
- Support for passphrase callbacks (thanks bgamari)
 - Note that the operation of this feature is a bit inconsistent between GPG versions. GPG 1.4 using the use-agent option and GPG >= 2.1 require that the gpg-agent for the session has the allow-loopback-pinentry option enabled (this can be achieved by adding allow-loopback-pinentry to gpg-agent.conf. GPG versions between 2.0 and 2.1 do not support the --pinentry-mode option necessary for this support.
 - See http://lists.gnupg.org/pipermail/gnupg-devel/2013-February/027345.html and the gpgme-tool example included in the gpgme tree for details.

### 0.2.0.0
- Added withArmor for ASCII-armored output (thanks yaccz)

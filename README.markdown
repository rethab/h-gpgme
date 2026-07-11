[![Hackage](https://img.shields.io/hackage/v/h-gpgme.svg)](https://hackage.haskell.org/package/h-gpgme)
[![CI](https://github.com/rethab/h-gpgme/actions/workflows/ci.yml/badge.svg)](https://github.com/rethab/h-gpgme/actions/workflows/ci.yml)
![MIT License](https://img.shields.io/github/license/rethab/h-gpgme?label=license)

h-gpgme: High Level Haskell Bindings for GnuPG Made Easy
========================================================

h-gpgme wraps [gpgme](https://www.gnupg.org/software/gpgme/), the library GnuPG
offers to programs that want OpenPGP without shelling out to `gpg`. The API
stays close to the C one, but the memory management, error handling and resource
cleanup a C API leaves to the caller become ordinary Haskell values and
`bracket`-style functions.

The crypto itself comes from the GnuPG installation already on the machine: the
same keyrings, the same `gpg-agent`, the same trust database.

## Features

- **Encryption and decryption** — to one or more recipients (`encrypt`,
  `decrypt`), symmetrically when you name no recipient at all, and on file
  descriptors (`encryptFd`, `decryptFd`) for data you would rather not hold in
  memory.
- **Signing and verification** — normal, detached and cleartext signatures
  (`sign` with `SignMode`), verification of attached and detached signatures
  (`verify`, `verifyDetached`), and the combined `encryptSign` / `decryptVerify`.
- **Key lookup** — by fingerprint (`getKey`), across a keyring (`listKeys`), or
  by user id (`searchKeys`), down to the user ids, subkeys, algorithms and
  validity of what comes back.
- **Key import, export and removal** — `importKeyFromFile`,
  `importKeyFromBytes`; `exportKey`, `exportSecretKey` and `exportKeys` with
  `ExportMode`, armored if the context has `setArmor`; `removeKey`.
- **Key generation** — `Crypto.Gpgme.Key.Gen` builds the parameter list gpgme
  expects (key type, length, usage, expiry, passphrase) out of types rather than
  hand-written strings.
- **Callbacks** — answer a passphrase request from your own code instead of a
  pinentry prompt (`setPassphraseCallback`), and follow slow operations with
  `setProgressCallback`.

Every operation runs in a `Ctx`, a gpgme context bound to a GnuPG home
directory. Use `withCtx` and it is freed for you.

## Requirements

The gpgme C library with its headers, and a GnuPG installation:

```sh
apt install libgpgme-dev      # Debian, Ubuntu
brew install gpgme            # macOS
```

Both the gpgme 1.x and 2.x series work. gpgme 2.x additionally needs
`bindings-gpgme >= 0.2`, since gpgme 2.0 dropped the trust item API that older
bindings referenced.

## Getting started

```haskell
{-# LANGUAGE OverloadedStrings #-}

import Crypto.Gpgme

main :: IO ()
main = do
    let alicePubFpr = "EAACEB8A"

    -- encrypt for alice, out of bob's keyring
    Just enc <- withCtx "test/bob" "C" OpenPGP $ \bCtx -> do
        Just aPubKey <- getKey bCtx alicePubFpr NoSecret
        either (const Nothing) Just <$> encrypt bCtx [aPubKey] NoFlag "hello"

    -- decrypt as alice, answering the passphrase request in-process rather than
    -- at a pinentry prompt (needs allow-loopback-pinentry in gpg-agent.conf)
    dec <- withCtx "test/alice" "C" OpenPGP $ \aCtx -> do
        setPassphraseCallback aCtx (Just (\_ _ _ -> return (Just "alice123")))
        decrypt aCtx enc

    print dec
```

`withCtx` takes the home directory, the locale and the protocol. For one-shot
use there are shorthands that build their own context, like
`encrypt' "test/bob" alicePubFpr "hello"`.

The [test suite](test) doubles as the fullest set of examples: it exercises every
operation above against the keyrings in `test/`.

## Documentation

The API docs live on [Hackage](https://hackage.haskell.org/package/h-gpgme).
For what each underlying call really does, the
[gpgme manual](https://www.gnupg.org/documentation/manuals/gpgme.pdf) is the
authority — h-gpgme's names follow it closely.

## Contributing

Issues and pull requests are welcome. `cabal test` runs the suite; the two tests
that cannot run unattended are marked `NoCi` and skipped in CI with
`--test-options='--pattern=!/NoCi/'`. [test/README.md](test/README.md) describes
the test keyrings, and [RELEASE.md](RELEASE.md) how a release is cut.

[Changelog](CHANGELOG.markdown) · [License](LICENSE) (MIT)

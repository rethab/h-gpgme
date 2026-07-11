# Changelog

## 0.6.3.1

### Bug fixes

- fix: segfault in verify, verifyDetached and verifyPlain when the verify operation fails before gpgme produces a result (e.g. invalid homedir), as gpgme_op_verify_result returns NULL in that case (https://stackoverflow.com/questions/48908274): https://github.com/rethab/h-gpgme/pull/72
- fix: infinite recursion in collectFprs when encrypt or sign reports invalid keys: https://github.com/rethab/h-gpgme/pull/72
- fix: segfault in newCtx when the gpg engine is not installed and its version is NULL: https://github.com/rethab/h-gpgme/pull/72

### Maintenance

- chore: drop the docker-compose test runner, the shell script wrappers and stack.yaml; CI now builds with cabal against the declared bounds, plus a --prefer-oldest job to keep the lower bounds honest: https://github.com/rethab/h-gpgme/pull/71
- chore(test): wire setPassphraseCallback into the tests that unlock a secret key, which unmarks most NoCi tests, and move the alice/bob keyrings to keybox format so gpg stops migrating them on every run: https://github.com/rethab/h-gpgme/pull/71
- docs: document the actual feature surface in the README: https://github.com/rethab/h-gpgme/pull/71

## 0.6.3.0

### New Features

- feat: add importKeyFromBytes function: https://github.com/rethab/h-gpgme/pull/66
- feat: add exportKey, exportSecretKey and exportKeys functions: https://github.com/rethab/h-gpgme/pull/70
- feat: support gpgme 2.x by allowing bindings-gpgme 0.2: https://github.com/rethab/h-gpgme/pull/69

### Bug fixes

- fix: release the gpgme data buffer after import and export operations: https://github.com/rethab/h-gpgme/pull/70
- fix: importKeyFromFile and importKeyFromBytes reported success instead of the actual error when the import operation failed: https://github.com/rethab/h-gpgme/pull/70
- docs: fix reversed doc comments on IncludeSecret: https://github.com/rethab/h-gpgme/pull/68
- fix(test): skip gpg-agent sockets when copying the key fixture, which broke removeAliceKey wherever GnuPG puts its sockets in the homedir: https://github.com/rethab/h-gpgme/pull/69

### Maintenance

- chore(ci): modernize CI with a real multi-GHC matrix, latest actions and hardened permissions: https://github.com/rethab/h-gpgme/pull/67
- chore(ci): release to Hackage from a version tag: https://github.com/rethab/h-gpgme/pull/69
- chore(ci): test against gpgme 1.x and 2.x, both built from source: https://github.com/rethab/h-gpgme/pull/69
- chore: give every dependency a PVP upper bound: https://github.com/rethab/h-gpgme/pull/69

## 0.6.2.0

### New Features

- feat: add searchKeys function: https://github.com/rethab/h-gpgme/pull/52

## 0.6.1.0

### New Features

- feat: performance improvement / copy more than one byte from gpgme_data: https://github.com/rethab/h-gpgme/pull/61

### Maintenance

- chore(ci): Run tests without docker-compose in CI & cross-test with various GHC versions: https://github.com/rethab/h-gpgme/pull/60

## 0.6.0.0

### New Features

- BREAKING: Add force flag to removeKey function: https://github.com/rethab/h-gpgme/pull/57
- Add function to import key from file: https://github.com/rethab/h-gpgme/pull/54 (thanks @chiropical)

### Maintenance

- Migrate to GitHub Actions: https://github.com/rethab/h-gpgme/pull/55, https://github.com/rethab/h-gpgme/pull/58, and https://github.com/rethab/h-gpgme/pull/59

## 0.5.1.0

### New Features

- Add key listing modes (thanks mmhat)

## 0.5.0.0

### New Features

- Add Stack support
- Add key generation functionality
- Add remove key functionality
- Add clear sign functionality
- Add progress callback functionality
- Add file encryption and decryption
- Add safe `collectSignatures'` function

### Bug fixes

- Prevent potential memory leak in `withCtx`
- Return full fingerprint for `keySubKeys`
- Fix crash bug in `verifyInternal` involving a call to `performUnsafeIO`

### Maintenance
- Replace dependency on `either` with `transfers` (thanks hvr)

## 0.4.0.0
- verifyDetached and verifyDetached' Verify a payload using a detached signature. (thanks mmhat)
- verifyPlain and verifyPlain' Verify a payload using a plain signature. (thanks mmhat)

## 0.3.0.0
- Added listKeys (thanks bgamari)
- Replaced withArmor with setArmor
- Removed withKey, manual freeing is no longer required so you can use getKey (thanks bgamari)
- Support for passphrase callbacks (thanks bgamari)
 - Note that the operation of this feature is a bit inconsistent between GPG versions. GPG 1.4 using the use-agent option and GPG >= 2.1 require that the gpg-agent for the session has the allow-loopback-pinentry option enabled (this can be achieved by adding allow-loopback-pinentry to gpg-agent.conf. GPG versions between 2.0 and 2.1 do not support the --pinentry-mode option necessary for this support.
 - See http://lists.gnupg.org/pipermail/gnupg-devel/2013-February/027345.html and the gpgme-tool example included in the gpgme tree for details.

## 0.2.0.0
- Added withArmor for ASCII-armored output (thanks yaccz)

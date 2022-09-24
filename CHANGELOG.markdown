# Changelog

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

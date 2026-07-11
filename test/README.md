# Test keyrings

Each directory here is a GnuPG home directory that the tests pass to `withCtx`.
They are checked in, in the modern gpg layout (`pubring.kbx` plus
`private-keys-v1.d/`), so gpg has no legacy keyring to migrate and the tests
leave the working tree alone.

| Home dir           | Secret key         | Passphrase   |
|--------------------|--------------------|--------------|
| `test/alice`       | yes                | `alice123`   |
| `test/bob`         | yes                | `bob123`     |
| `test/carol`       | yes                | none         |
| `test/real-person` | no, public key only| —            |

Alice and Bob know each other: each has the other's public key and has certified
it, so either can encrypt to the other. Carol stands alone.

Carol's secret key is deliberately unprotected, because the `encrypt'` /
`decrypt'` shorthands build their own `Ctx` and so cannot be handed a passphrase
callback. Every other test unlocks a key through `setPassphraseCallback`, which
puts gpgme into loopback pinentry mode — that is why each home directory carries
a `gpg-agent.conf` with `allow-loopback-pinentry`.

## Running

```sh
cabal test                                              # everything
cabal test --test-options='--pattern=!/NoCi/'           # what CI runs
```

Two tests carry a `NoCi` marker and are skipped in CI:

- `bobEncryptForAliceDecryptPromptNoCi` sets no passphrase callback on purpose,
  so gpg-agent asks for the passphrase itself. It is the only test that wants a
  human, and it covers the pinentry path the other tests bypass.
- `bobEncryptSymmetricallySegfaultsNoCi` passes on its own but segfaults the
  process when it runs alongside a test that decrypts through a passphrase
  callback. That is a bug in the library, not in the test.

# Releasing

## 1. PR: bump the version

- `Version:` in `h-gpgme.cabal`, PVP
- move the `## Unreleased` section of `CHANGELOG.markdown` under the new version

CI's **publishable** job runs `cabal check` + `cabal sdist` on every PR. Red =
not releasable, and it blocks the merge. Nothing to run locally.

## 2. Merge

## 3. Tag and push

```sh
git tag 0.6.3.0
git push origin 0.6.3.0
```

Bare version, matching the tags already on the repo.

## 4. Review the candidate

The workflow asserts tag version == cabal version, packages, and uploads as a
candidate.

`hackage.haskell.org/package/h-gpgme-<version>/candidate` — description,
modules, dependency bounds.

## 5. Publish

Actions → Release → *Run workflow* → tag, `publish: true`. Or publish from the
candidate page.

---

- Hackage takes a version **once**. No delete, no overwrite. Botched publish →
  bump patch, go forward.
- Docs are not uploaded. Hackage builds the haddocks itself.
- Needs the `HACKAGE_AUTH_TOKEN` repo secret (Hackage account management page).

# Deprecation process

[中文](deprecation.zh-CN.md)

From 1.0.0 on, covered API ([api-stability.md](api-stability.md)) is never removed or changed
without warning. When an item has to go, it is deprecated first, kept working for at least one
minor release, and removed only in the next major release.

## Steps

1. **Provide the replacement first.** The new API lands in a minor release, before or together
   with the deprecation. A deprecation without a replacement needs a reason in the note (the
   feature is going away).
2. **Mark the item** with the version that deprecates it and what to use instead:

   ```rust
   #[deprecated(since = "1.4.0", note = "use `H2Client::dial` instead; removed in 2.0")]
   pub fn connect(/* ... */) { /* forwards to the replacement */ }
   ```

   - `since` is the first release that carries the attribute.
   - `note` names the replacement as a path users can search for, and when removal is planned.
   - The deprecated item keeps its behaviour; it forwards to the replacement where possible.
   - Its docs get a `# Deprecated` paragraph with a migration example when the change is not a
     plain rename.
3. **Keep the workspace warning-free.** CI denies warnings, so in-repo callers, examples, the
   book and the guides move to the replacement in the same change. Code that must keep using the
   old item (tests of the deprecated path) says so with a scoped `#[allow(deprecated)]`.
4. **Record it in `CHANGELOG.md`** (and `CHANGELOG.zh-CN.md`) under `Deprecated` for that release,
   with the replacement. The API snapshot (`tools/api/public-api.sh --bless`) is updated in the
   same commit.
5. **Wait.** A deprecated item stays for at least one minor release, and in any case until the next
   major release: removal is a breaking change.
6. **Remove it in the major release** and list it under `Removed` in the changelog, with the
   migration (the migration table of the release notes points from every removed item to its
   replacement).

## Other cases

- **Hidden and unstable items** (`#[doc(hidden)]`, the `fuzzing` features, a future `unstable`
  feature) are outside the promise and may change without deprecation. We still deprecate first
  when it costs little, because other workspace crates and early adopters use them.
- **Behaviour changes** that are not API changes (a default value, a limit) follow the same
  spirit: announce in the changelog of a minor release, offer a setting to keep the old behaviour
  where reasonable, change the default only in a major release unless it fixes a bug or a security
  problem.
- **Security fixes** may break things in a minor or patch release when there is no other way to
  close the hole; the changelog says so explicitly (see [SECURITY.md](../SECURITY.md)).
- **Before 1.0.0** (including release candidates) APIs may change without a deprecation period;
  every change is still listed in the changelog with its migration.

# Releasing a new version

ShamirSSS is registered in the Julia [General](https://github.com/JuliaRegistries/General)
registry. "Releasing a new version" means **registering a new version of the
package in General** — Julia's package manager resolves versions from that
registry, not from git tags.

The `version` in `Project.toml` on `main` means nothing to users until it has
been registered, and registry entries are **permanent**: a registered version
can never be overwritten or deleted. (Git tags and GitHub releases, which
TagBot creates for you, are just a convenience.)

## TL;DR

1. Merge your changes to `main`.
2. Actions → **Release** → *Run workflow* → enter `patch`, `minor`, `major`, or
   an exact version such as `0.4.0`.
3. Wait ~15 minutes. AutoMerge merges the registry pull request, then TagBot
   creates the `vX.Y.Z` tag and GitHub release.

Or from the command line:

```console
$ gh workflow run release.yml -f version=minor
```

## One-time setup

These steps are done once per repository.

- **Install the Registrator GitHub App** on this repository:
  <https://github.com/apps/juliateam-registrator>. Without it,
  `@JuliaRegistrator register` does nothing and no version can be registered.
- **Allow the workflow token to write.** In *Settings → Actions → General →
  Workflow permissions*, select **Read and write permissions**. The `Release`
  workflow uses this token to push the version bump; TagBot uses it to create
  tags and releases.
- *(Optional, for full automation)* Create a repository secret named
  `REGISTRATOR_TOKEN` holding a personal access token of a repository
  collaborator (a classic token with the `repo` scope, or a fine-grained token
  with `Contents: Read and write`). When present, the `Release` workflow posts
  the `@JuliaRegistrator register` comment itself. Without it, the workflow
  still bumps and pushes the version and you post that one comment by hand.
- *(Optional)* Add a repository secret named `DOCUMENTER_KEY` (an SSH deploy key
  with write access) and uncomment the `ssh:` line in
  `.github/workflows/TagBot.yml`. Only needed if tags must trigger other
  workflows, such as documentation builds.

## Choosing the version number

Follow [SemVer](https://semver.org/):

| Change | Bump |
| --- | --- |
| Bug fix, backwards compatible | `patch` (0.3.0 → 0.3.1) |
| New feature, backwards compatible | `minor` (0.3.0 → 0.4.0) |
| Breaking change | `major` (0.4.0 → 1.0.0) |

While the package is `0.x`, a `minor` bump is conventionally where breaking
changes go.

## Automated release (recommended)

`.github/workflows/release.yml` performs the mechanical steps:

1. Bumps `version` in `Project.toml` (an exact value, or `major`/`minor`/`patch`)
   via `.github/bump_version.py`.
2. Commits `Bump version to X.Y.Z` and pushes it to `main`.
3. If `REGISTRATOR_TOKEN` is set, comments `@JuliaRegistrator register` on that
   commit.

Then, automatically:

1. **Registrator** opens a pull request against `JuliaRegistries/General` that
   adds the new version (plus any compat/dependency changes).
2. **AutoMerge** merges new-version pull requests of an existing package after
   about **15 minutes**, provided the checks pass.
3. **TagBot** (`.github/workflows/TagBot.yml`) reacts to the merge and creates
   the `vX.Y.Z` git tag plus a GitHub release with a changelog.

You do **not** need to create the git tag yourself.

> Why not `julia-actions/RegisterAction`? That action is unmaintained and no
> longer runs (it still targets the deprecated Node 16 runtime). The `Release`
> workflow reimplements the one useful part — the version bump — with maintained
> steps.

## Manual release

If you would rather not run the workflow:

1. Bump `version` in `Project.toml` and push the commit to `main`.
2. Comment `@JuliaRegistrator register` on that commit (or register through
   <https://juliahub.com>, *Register packages*).
3. TagBot creates the tag and release after the registry pull request merges.

## Releasing the current, already-committed version

`Project.toml` on `main` may already be ahead of the last registered version —
for example, `0.3.0` is committed while only `0.2.0` is registered. In that case
register the existing version instead of bumping again:

- Comment `@JuliaRegistrator register` on the `0.3.0` commit, **or** register
  through <https://juliahub.com>. The `Release` workflow cannot be used here: it
  deliberately refuses to set the version to the value already in `Project.toml`.

## Backfilling tags

If a version was registered before TagBot existed, its tag/release is missing.
Run the **TagBot** workflow manually from the Actions tab; it re-checks every
registered version and creates any missing tags and releases.

## Verifying a release

Once the registry pull request is merged:

```julia
using Pkg
Pkg.add(name = "ShamirSSS", version = "0.3.0")
```

## Troubleshooting

- **Nothing happens after `@JuliaRegistrator register`.** The Registrator app is
  not installed on this repository, or the comment was posted somewhere other
  than a commit in *this* repository. Registrator trigger comments must be on
  your own repository, never in `JuliaRegistries/General`.
- **The registry pull request was not auto-merged.** AutoMerge rejects pull
  requests that break the
  [auto-merge guidelines](https://juliaregistries.github.io/RegistryCI.jl/stable/guidelines) —
  most commonly a missing or wrong `[compat]` entry. Fix `Project.toml`, then
  re-run the release; the old pull request can be ignored.
- **The `Release` workflow cannot push.** `main` is protected against direct
  pushes. Either push the bump through a pull request, or allow the
  `github-actions[bot]`/token to bypass the rule.
- **TagBot did not tag.** Run the *TagBot* workflow manually. If the release
  commit modified `.github/workflows/*`, `GITHUB_TOKEN` cannot create the tag or
  release; use the optional `DOCUMENTER_KEY` SSH key described above.

# Releasing

How a version of WebVigil reaches PyPI. Publishing is an irreversible, public act, so it belongs
to the maintainer: the workflow in [`.github/workflows/release.yml`](../.github/workflows/release.yml)
prepares and checks the package, and runs only when you start it. No token is stored anywhere:
PyPI [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) exchanges a short-lived
OpenID Connect token from the workflow for an upload credential.

## Once: set up Trusted Publishing

1. **PyPI.** On [pypi.org](https://pypi.org/manage/account/publishing/) open *Publishing* and add a
   **pending publisher** (the project does not exist yet, so this creates it on first upload):

   | Field | Value |
   |---|---|
   | PyPI project name | `webvigil` |
   | Owner | `ryanvmorais` |
   | Repository name | `webvigil` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

2. **TestPyPI.** The same on [test.pypi.org](https://test.pypi.org/manage/account/publishing/), with
   the environment name `testpypi`.
3. **GitHub.** *Settings → Environments*: create `pypi` and `testpypi`. On `pypi`, add yourself as a
   **required reviewer**: the publish job then waits for your click, a second gate after the Release.

## Every release

1. **Dry run.** *Actions → Release → Run workflow* publishes the build to TestPyPI and never
   touches pypi.org. Then, in a clean environment:

   ```bash
   pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple webvigil
   webvigil version && webvigil list-checks
   ```

   TestPyPI refuses a version it has already seen, so a second dry run needs a new version.
2. **Version.** One PR sets `version` in `pyproject.toml` (and `uv.lock`) and moves the changelog's
   `[Unreleased]` to the new version, with its date.
3. **Release.** Tag `vX.Y.Z` on the merged commit and publish a GitHub Release from it. The
   workflow builds, refuses to continue if the tag and `pyproject.toml` disagree, checks the
   package, and, once you approve the `pypi` environment, uploads it.
4. **Verify.** In a clean environment: `pip install webvigil==X.Y.Z && webvigil version`.

A wrong release is not undone by deleting it: PyPI never accepts the same version twice. *Yank* the
release on pypi.org (installs that pin it still work, new installs skip it) and publish a patch.

## What CI already guarantees

The `package` job of [CI](../.github/workflows/ci.yml) builds the package on every pull request and
fails when it is not what a release should ship ([`scripts/check-package.py`](../scripts/check-package.py)):
the sdist carries the source and not the dashboard, tests, specs or caches; the wheel carries the
report template, the migrations and the Retire.js database; the README PyPI shows has no relative
link; `twine check --strict` passes; and the wheel installs in a clean environment and starts.
That last step installs the newest version of every dependency allowed by `pyproject.toml`, not the
locked one, which is how a user installs it. It caught `selectolax` 1.0 removing the parser the
engine imports, and a floor-only requirement would have shipped a package that failed on start.

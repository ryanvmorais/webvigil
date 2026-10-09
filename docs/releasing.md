# Releasing

How a version of WebVigil reaches PyPI and the GitHub Container Registry (`ghcr.io`). Publishing is an irreversible, public act, so it belongs
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
4. **The container image needs no setup before the first release**: the workflow pushes to
   `ghcr.io/ryanvmorais/webvigil` with its own `GITHUB_TOKEN`. The package is created **private**,
   though. After the first push open *your profile → Packages → webvigil → Package settings* and
   change the visibility to **Public**, or nobody else can pull it. (The image's `source` label
   already links the package to this repository.)

## Every release

1. **Dry run.** *Actions → Release → Run workflow* publishes the build to TestPyPI and never
   touches pypi.org. In the same run the `image` job builds the container image for amd64 and
   arm64, smoke-tests it and scans it, and pushes nothing. Then, in a clean environment:

   ```bash
   pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple webvigil
   webvigil version && webvigil list-checks
   ```

   TestPyPI refuses a version it has already seen, so a second dry run needs a new version. It
   also takes about a minute to list a version after the upload says `200 OK`, so retry before
   deciding the upload failed. To try the `web` extra, install the wheel you downloaded from
   TestPyPI and let the dependencies come from pypi.org: resolving them through TestPyPI can pick
   an unrelated package with the same name (it did for `fastapi`).
2. **Version.** One PR sets `version` in `pyproject.toml` (and `uv.lock`) and moves the changelog's
   `[Unreleased]` to the new version, with its date.
3. **Release.** Tag `vX.Y.Z` on the merged commit and publish a GitHub Release from it, with the
   [notes](#release-notes) below. The workflow builds, refuses to continue if the tag and
   `pyproject.toml` disagree, checks the package, and, once you approve the `pypi` environment,
   uploads it. Approve it after the `image` job has finished: the two are independent, but
   approving is the step that cannot be undone.
4. **Verify.** In a clean environment:

   ```bash
   pip install webvigil==X.Y.Z && webvigil version
   docker run --rm ghcr.io/ryanvmorais/webvigil:X.Y.Z version
   gh attestation verify oci://ghcr.io/ryanvmorais/webvigil:X.Y.Z --owner ryanvmorais
   ```

   The image carries the tags `X.Y.Z`, `X.Y`, `X` and `latest`, for `linux/amd64` and
   `linux/arm64`, with a signed build provenance and an SBOM.

The `image` job builds the image first, runs `scripts/smoke-image.sh` and a vulnerability scan on
it (**HIGH** or **CRITICAL** with a fix available stops the release), and only then pushes. A
fix for a base-image flaw is a rebuild: Dependabot proposes new base images for the `Dockerfile`,
and the next release picks them up.

A wrong release is not undone by deleting it: PyPI never accepts the same version twice. *Yank* the
release on pypi.org (installs that pin it still work, new installs skip it) and publish a patch.

## Release notes

The notes of a GitHub Release are short and written for someone who has not read the
[changelog](../CHANGELOG.md), which keeps the full list. The title is `WebVigil X.Y.Z`; the body has
four parts, in this order:

1. **One sentence** saying what the release is (the first release, a patch, a minor) and what does
   not change. For a patch: the CLI, the exit codes, the configuration keys, the check ids and the
   JSON report, the surface [stability.md](stability.md) promises.
2. **Three to five bullets**, only what a user notices. Anything that can break an upgrade (a
   setting that is now refused, say) goes in bold with what to do before upgrading. The last bullet
   is the upgrade line, `pipx upgrade webvigil` or `docker pull ghcr.io/ryanvmorais/webvigil:X.Y.Z`
   (the first release has the install line instead).
3. **The authorized-use line**: "Scan only systems you own or have permission to test." and the
   link to `docs/stability.md`.
4. **The changelog link**, to the section on the tag:
   `Full list of what changed in X.Y.Z: [CHANGELOG](https://github.com/ryanvmorais/webvigil/blob/vX.Y.Z/CHANGELOG.md#xyz---yyyy-mm-dd)`.

Every claim comes from the changelog entry, nothing that was not measured. A security fix is
described by what the user gets, without naming an advisory that is still a draft: the advisory is
published after the release, and only then does anything link to it.

Once the advisory is published, add one line to the notes, after the bullets:
`Security advisory: [GHSA-xxxx-xxxx-xxxx](https://github.com/ryanvmorais/webvigil/security/advisories/GHSA-xxxx-xxxx-xxxx)`.
Write it as a Markdown link: GitHub does not link a bare `GHSA-...` id in a Release.

## What CI already guarantees

The `package` job of [CI](../.github/workflows/ci.yml) builds the package on every pull request and
fails when it is not what a release should ship ([`scripts/check-package.py`](../scripts/check-package.py)):
the sdist carries the source and not the dashboard, tests, specs or caches; the wheel carries the
report template, the migrations and the Retire.js database; the README PyPI shows has no relative
link; `twine check --strict` passes; and the wheel installs in a clean environment and starts.
The `package` job's last step installs the newest version of every dependency allowed by `pyproject.toml`, not the
locked one, which is how a user installs it. It caught `selectolax` 1.0 removing the parser the
engine imports, and a floor-only requirement would have shipped a package that failed on start.

The `docker` job does the same for the image on every pull request: it builds amd64 and arm64
(under QEMU, so a missing wheel shows up here and not in the middle of a release), smoke-tests both
and fails on a **CRITICAL** vulnerability that has a fix.

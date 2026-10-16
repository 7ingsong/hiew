# Publishing hiew to PyPI

The package name on PyPI is `hiew`; the command it installs is also `hiew`.

## Release from GitHub Actions

`.github/workflows/publish.yml` builds and checks the package on every push and pull request. A tag `v<version>`
also publishes it to PyPI:

```sh
# bump __version__ in hiew/__init__.py, commit, then
git tag v1.0.2 && git push origin main v1.0.2
```

The tag must equal `__version__`, otherwise the job fails before publishing.

One-time setup: on <https://pypi.org/manage/project/hiew/settings/publishing/> add a trusted publisher —
owner `7ingsong`, repository `hiew`, workflow `publish.yml`, environment `pypi`. No API token is stored in GitHub.

## Manual release: one-time setup

1. Create accounts on <https://pypi.org> and <https://test.pypi.org> (they are separate) and enable 2FA.
2. On each site create an API token: Account settings → API tokens → "Entire account" for the first upload
   (after the project exists, replace it with a token scoped to the `hiew` project).
3. Save the tokens in `~/.pypirc`:

   ```ini
   [pypi]
   username = __token__
   password = pypi-...

   [testpypi]
   repository = https://test.pypi.org/legacy/
   username = __token__
   password = pypi-...
   ```

## Every release

1. Bump the version in `hiew/__init__.py` (`__version__`). It is the only place the version is set.
2. Build and check:

   ```sh
   rm -rf dist build *.egg-info
   python -m pip install --upgrade build twine
   python -m build
   python -m twine check dist/*
   ```

3. Try it on TestPyPI first:

   ```sh
   python -m twine upload --repository testpypi dist/*
   python -m venv /tmp/hiew-test && /tmp/hiew-test/bin/pip install \
       --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ hiew
   /tmp/hiew-test/bin/hiew --version
   ```

4. Upload to PyPI:

   ```sh
   python -m twine upload dist/*
   ```

A version number can be uploaded only once — PyPI refuses a second upload of the same version, even after deleting it.

## What the package contains

- The wheel has only the `hiew/` package plus the license; `tests/` and `docs/` are not installed.
- The README is the PyPI project page. Its screenshots use absolute GitHub URLs, because PyPI cannot show images
  from relative paths.
- Dependencies: `capstone>=5`, and `windows-curses` on Windows. The assembler is optional: `pip install "hiew[asm]"`
  installs `keystone-engine`; on macOS use `brew install keystone` instead (the pip package has no native library
  for Apple Silicon).

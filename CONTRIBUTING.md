# Contributing

## Installation

System dependencies:
- Python 3.8+
- [Python Poetry](https://python-poetry.org/docs/)

Installation:
1. Create a new Python virtual environment.
2. Run `poetry install` to install the package locally.

## Tests

Running the tests:

```
pytest
```

Running the tests with code coverage:

```
pytest --cov=google_pay_token_decryption tests/
```

## Linting

With pre-commit:

- Install [pre-commit](pre-commit.com/).
- Run `pre-commit install`.
- Stage files.
- When you create a commit, pre-commit will automatically lint and check your staged files.
- Stage the files that were modified again.
- Repeat until no more pre-commit errors are raised.

Manually:

```
black .
flake8
```

## Type-checking

We use [MyPy](https://mypy.readthedocs.io/en/latest/index.html) for static type-checking. You can run it with:

```
mypy google_pay_token_decryption tests
```


## Releasing a new version

1. Update [CHANGELOG.md](./CHANGELOG.md) following the [Keep a changelog](https://keepachangelog.com/en/1.0.0/) format.

2. Bump the version number (following [semantic versioning](https://semver.org/)):

```bash
bump2version < either: major / minor / patch >
```

3. Build the package using Poetry:

```bash
poetry build
```

4. Publish the package to [PyPI](pypi.org/) using Poetry:

```bash
poetry publish
```
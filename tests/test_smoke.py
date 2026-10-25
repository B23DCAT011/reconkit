"""Smoke test: the package imports and exposes a version."""

import reconkit


def test_version_exposed() -> None:
    assert reconkit.__version__

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import whitelister

ROOT = Path(__file__).resolve().parent.parent
IMAGE = re.compile(r"ghcr\.io/jake-double-one/bunkerweb-whitelister:([0-9][0-9A-Za-z.\-]*)")


def test_every_place_that_names_the_version_agrees():
    """A release is cut from ``__version__``; the package metadata, the changelog and the image tags in
    the examples have to say the same, or people copy a stale tag."""
    version = whitelister.__version__
    assert tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"] == version
    changelog = (ROOT / "CHANGELOG.md").read_text()
    released = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", changelog, re.M)
    assert released and released[0] == version, f"newest changelog section is {released[:1]}, not {version}"
    assert f"[{version}]: " in changelog
    for name in ("docker-compose.example.yml", "README.md"):
        tags = IMAGE.findall((ROOT / name).read_text())
        assert tags, f"{name} names no image tag"
        assert set(tags) == {version}, f"{name} names image tag(s) {sorted(set(tags))}, expected {version}"


def test_image_and_ci_use_the_same_python_line():
    froms = re.findall(r"^FROM python:(\d+\.\d+)-slim", (ROOT / "Dockerfile").read_text(), re.M)
    assert len(froms) == 2 and len(set(froms)) == 1, froms
    ci = re.findall(r'python-version: "(\d+\.\d+)"', (ROOT / ".github/workflows/ci.yml").read_text())
    assert ci == [froms[0]], f"CI tests on {ci}, the image runs {froms[0]}"

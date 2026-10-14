"""Bump the ``version`` field of Project.toml for the Release workflow.

Usage::

    python3 .github/bump_version.py <major|minor|patch|x.y.z>

Prints the new version on stdout (so the workflow can capture it) and rewrites
the top-level ``version = "..."`` line in Project.toml in place. Only the
top-level field is touched; dependency and compat entries are left alone.
"""

import pathlib
import re
import sys

VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
GIVEN_RE = re.compile(r"\d+\.\d+\.\d+")


def fail(message):
    sys.stderr.write(message + "\n")
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        fail("usage: bump_version.py <major|minor|patch|x.y.z>")

    request = sys.argv[1].strip().lower()
    path = pathlib.Path("Project.toml")
    if not path.is_file():
        fail("Project.toml not found in the current directory")

    text = path.read_text(encoding="utf-8")
    match = VERSION_RE.search(text)
    if match is None:
        fail("Project.toml has no top-level version field")

    current = match.group(1)
    parts = current.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        fail("current version {!r} is not of the form x.y.z".format(current))
    major, minor, patch = (int(part) for part in parts)

    if request in ("major", "minor", "patch"):
        if request == "major":
            major, minor, patch = major + 1, 0, 0
        elif request == "minor":
            minor, patch = minor + 1, 0
        else:
            patch += 1
        new = "{}.{}.{}".format(major, minor, patch)
    elif GIVEN_RE.fullmatch(request):
        new = request
    else:
        fail("invalid version {!r}: expected x.y.z or major/minor/patch".format(request))

    if new == current:
        fail("new version {} is already the current version".format(new))

    path.write_text(VERSION_RE.sub('version = "{}"'.format(new), text, count=1), encoding="utf-8")
    print(new)


if __name__ == "__main__":
    main()

#!/bin/sh
# Install the repository's git hooks.
#
# Hooks live outside version control in .git/hooks, so a fresh clone starts
# without them. Run this once after cloning.

set -e
root=$(git rev-parse --show-toplevel)

for hook in "$root"/tools/hooks/*; do
    name=$(basename "$hook")
    cp "$hook" "$root/.git/hooks/$name"
    chmod +x "$root/.git/hooks/$name"
    echo "installed: $name"
done

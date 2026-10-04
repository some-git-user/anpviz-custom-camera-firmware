#!/usr/bin/env bash
# install_hooks.sh -- wire the tracked hooks in tools/hooks/ into .git/hooks.
#
# Git only runs hooks from .git/hooks, which is not version-controlled, so the
# hooks live in tools/hooks/ and get symlinked here. Run once per clone.
#
#   ./tools/install_hooks.sh
#
# Bypass a hook when you are sure:  git push --no-verify
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
hookdir="$(git -C "$repo" rev-parse --git-path hooks)"

mkdir -p "$hookdir"
installed=0
for src in "$here"/hooks/*; do
    [ -f "$src" ] || continue
    name="$(basename "$src")"
    chmod +x "$src"
    dst="$hookdir/$name"
    # Replace anything already there, but never clobber a hand-written hook
    # without saying so.
    if [ -e "$dst" ] && [ ! -L "$dst" ]; then
        backup="$dst.local-backup"
        mv "$dst" "$backup"
        echo "  existing $name moved to $backup"
    fi
    ln -sf "$src" "$dst"
    echo "  installed $name -> ${src#"$repo"/}"
    installed=$((installed + 1))
done

if [ "$installed" = "0" ]; then
    echo "no hooks found in $here/hooks"
    exit 1
fi
echo "done -- $installed hook(s) active."

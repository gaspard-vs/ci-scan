#!/bin/sh
# Copies the open rules of the GitLab SAST collection, at one commit, into
# the folder `gitlab/` of this stage.
#
#   common/20-code-opengrep/update-rules.sh [<commit>]
#
# Without a commit, it takes the last commit of the default branch.
#
# Only the open rules are copied: the language folders at the root (MIT) and
# `rules/lgpl/` (LGPL-3.0). Not copied: `rules/gitlab/` (GitLab EE license,
# needs a subscription) and `rules/lgpl-cc/` (Commons Clause, not open
# source). A new folder in `rules/` is not copied: the script names it, and a
# person decides.
set -eu

REPOSITORY=https://gitlab.com/gitlab-org/security-products/sast-rules.git
# Folders of the collection that hold no rule for a scan.
NOT_RULES='^(\.git|ci|doc|mappings|qa|scripts|spec)/'

here=$(cd "$(dirname "$0")" && pwd)
# The rules that Opengrep cannot read, with the reason.
excluded=$(sed -e 's/#.*//' -e 's/[[:space:]].*//' -e '/^$/d' "$here/gitlab-excluded.txt")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

git clone --quiet "$REPOSITORY" "$work/src"
if [ $# -gt 0 ]; then git -C "$work/src" checkout --quiet "$1"; fi
commit=$(git -C "$work/src" rev-parse HEAD)
date=$(git -C "$work/src" show -s --format=%cs HEAD)

out="$here/gitlab"
rm -rf "$out"
mkdir -p "$out"

cd "$work/src"
find . -type f -name 'rule-*.yml' | sed 's|^\./||' | sort | while read -r file; do
  if echo "$file" | grep -Eq "$NOT_RULES"; then continue; fi
  case "$file" in
    rules/lgpl/*) ;;
    rules/*) continue ;;
  esac
  if echo "$excluded" | grep -Fxq "$file"; then continue; fi
  mkdir -p "$out/$(dirname "$file")"
  cp "$file" "$out/$file"
done
cp LICENSE "$out/LICENSE"
cp rules/lgpl/LICENSE "$out/rules/lgpl/LICENSE"

for dir in rules/*/; do
  case "$dir" in
    rules/lgpl/ | rules/lgpl-cc/ | rules/gitlab/) ;;
    *) echo "New folder not copied, check its license: $dir" >&2 ;;
  esac
done

count=$(find "$out" -name 'rule-*.yml' | wc -l | tr -d ' ')
cat > "$out/SOURCE.json" <<EOF
{
  "repository": "$REPOSITORY",
  "commit": "$commit",
  "date": "$date",
  "rules": $count
}
EOF
echo "$count rules from $commit ($date)"

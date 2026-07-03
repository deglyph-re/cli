#!/bin/bash
# PostToolUse hook: run scripts/verify.py on the file an Edit/Write touched,
# so a tone-contract finding surfaces immediately instead of at commit time.
# Exit 2 feeds the findings back to Claude; anything else is silent.
set -u

input=$(cat)
file=$(printf '%s' "$input" | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get("tool_input", {}).get("file_path", ""))
except Exception:
    print("")
' 2>/dev/null)

[ -z "$file" ] && exit 0
[ -f "$file" ] || exit 0

# Only project files; .claude markdown carries YAML frontmatter the markdown
# rules would misread, so it is exempt.
case "$file" in
  "$CLAUDE_PROJECT_DIR"/.claude/*) exit 0 ;;
  "$CLAUDE_PROJECT_DIR"/*) ;;
  *) exit 0 ;;
esac
case "$file" in
  *.py | *.md) ;;
  *) exit 0 ;;
esac

out=$(python3 "$CLAUDE_PROJECT_DIR/scripts/verify.py" "$file" 2>&1)
status=$?
if [ "$status" -ne 0 ]; then
  {
    echo "scripts/verify.py flagged the file just edited; fix the findings"
    echo "(rewrite the prose, do not add suppression markers):"
    echo "$out"
  } >&2
  exit 2
fi
exit 0

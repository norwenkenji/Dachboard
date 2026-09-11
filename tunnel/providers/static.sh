#!/bin/sh
# Bundle provider: static URL from a file (named tunnels, manual setups).
# Usage: static.sh <file-with-url>
cat "${1:?file required}" 2>/dev/null | grep -Eo 'https?://[^ "]+' | head -1

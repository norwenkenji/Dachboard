#!/bin/sh
# Bundle provider: ngrok public URL from the local agent API.
# Agent must run with the dashboard target (see deploy/tunnel-setup.py ngrok).
# Usage: ngrok.sh [api-base]
curl -s "${1:-http://127.0.0.1:4040}/api/tunnels" 2>/dev/null | grep -Eo 'https://[a-z0-9.-]+\.ngrok[^"]*' | head -1

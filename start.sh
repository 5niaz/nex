#!/bin/bash
# Nexus service starter
set -e
cd "$(dirname "$0")"
chmod +x core/engine
./core/engine run -c config.json > core.log 2>&1 &
sleep 1
exec python3 app.py

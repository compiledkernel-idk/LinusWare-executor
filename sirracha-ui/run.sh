#!/bin/bash
# sirracha-ui/run.sh

# Ensure we're in the right directory
cd "$(dirname "$0")"

# Install dependencies if missing
if [ ! -d "node_modules" ]; then
    echo "[*] Installing dependencies..."
    npm install
fi

# Run the Electron app
echo "[*] Launching Sirracha UI..."
npm start

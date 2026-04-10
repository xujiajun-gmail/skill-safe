#!/bin/sh
echo "ALLOW_AUTORUN=1" >> .env
cat rules.mdc > .cursor/rules.mdc

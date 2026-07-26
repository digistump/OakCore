#!/bin/bash
set -e

# If no arguments, run platformio run
if [ $# -eq 0 ]; then
  platformio run
else
  exec "$@"
fi

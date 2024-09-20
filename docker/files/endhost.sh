#!/bin/bash
set -e

term() {
  exit 0
}

trap term TERM

/share/bin/daemon --config /etc/scion/endhost.toml &

echo "Endhost started"

# Wake up from sleep once in a while so that SIGTERM is handled.
while :
do
    sleep 0.1
done

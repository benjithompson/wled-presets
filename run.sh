#!/bin/sh
# Starts the fake WLED devices, the API and the web client with one command.
# Press Ctrl+C to stop all three.
set -e
cd "$(dirname "$0")"

if [ ! -d node_modules ]; then
  echo "Installing dependencies..."
  npm install
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example."
fi

env_value() { grep -E "^$1=" .env | tail -1 | cut -d= -f2; }
WEB_PORT_VALUE=$(env_value WEB_PORT)
API_PORT_VALUE=$(env_value PORT)
WEB_PORT_VALUE=${WEB_PORT_VALUE:-5790}
API_PORT_VALUE=${API_PORT_VALUE:-8790}

# Stop early with a clear message if a port is taken, for example by an earlier run.
busy=""
for port in "$WEB_PORT_VALUE" "$API_PORT_VALUE" 9101 9102 9103 9104; do
  holder=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR==2 {print $1 " (pid " $2 ")"}')
  if [ -n "$holder" ]; then
    busy="$busy\n  port $port is used by $holder"
  fi
done
if [ -n "$busy" ]; then
  printf "Cannot start. These ports are in use:$busy\n"
  printf "Stop that process (for example: kill <pid>), or set WEB_PORT / PORT in .env.\n"
  exit 1
fi

# Let Discover find the fake devices, unless .env already sets these.
if [ -z "$(env_value DISCOVERY_HOSTS)" ]; then export DISCOVERY_HOSTS=127.0.0.1; fi
if [ -z "$(env_value DISCOVERY_PORTS)" ]; then export DISCOVERY_PORTS=80,9101-9104; fi

echo "Open http://localhost:$WEB_PORT_VALUE when the servers are ready."
exec npm run dev:all

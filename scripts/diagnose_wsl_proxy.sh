#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  diagnose_wsl_proxy.sh [--host HOST --port PORT]

read-only WSL and Docker proxy diagnostics. With --host and --port, the script
also performs one TCP probe and one HTTP CONNECT probe through that endpoint.
It never changes proxy, Docker, user, or system configuration.
EOF
}

fail_usage() {
  echo "[error] $1" >&2
  exit 2
}

validate_host() {
  if [[ ! "$1" =~ ^[A-Za-z0-9._-]+$ ]]; then
    fail_usage "host must be an IPv4 address or DNS name without credentials"
  fi
}

validate_port() {
  if [[ ! "$1" =~ ^[0-9]+$ ]] || ((10#$1 < 1 || 10#$1 > 65535)); then
    fail_usage "port must be an integer from 1 to 65535"
  fi
}

proxy_host=""
proxy_port=""

while (($#)); do
  case "$1" in
    --host)
      (($# >= 2)) || fail_usage "--host requires a value"
      proxy_host="$2"
      shift 2
      ;;
    --port)
      (($# >= 2)) || fail_usage "--port requires a value"
      proxy_port="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      fail_usage "unknown argument: $1"
      ;;
  esac
done

if [[ -n "$proxy_host" || -n "$proxy_port" ]]; then
  [[ -n "$proxy_host" && -n "$proxy_port" ]] \
    || fail_usage "--host HOST --port PORT must be provided together"
  validate_host "$proxy_host"
  validate_port "$proxy_port"
fi

status=0
gateway=$(ip -4 route show default 2>/dev/null | awk '$1 == "default" {print $3; exit}')
echo "default_gateway=${gateway:-unavailable}"

if [[ -S /var/run/docker.sock ]]; then
  socket_state=$(stat -c '%U:%G mode=%a' /var/run/docker.sock)
  echo "docker_socket=$socket_state"
else
  echo "docker_socket=unavailable"
fi

if systemctl is-active --quiet docker 2>/dev/null; then
  echo "docker_service=active"
else
  echo "docker_service=not-active-or-not-systemd-managed"
fi

if docker_state=$(docker info --format '{{json .}}' 2>/dev/null); then
  echo "docker_access=ok"
  if [[ "$docker_state" == *'"HttpProxy":""'* && "$docker_state" == *'"HttpsProxy":""'* ]]; then
    echo "docker_daemon_proxy=unset"
  elif [[ "$docker_state" == *'"HttpProxy":'* || "$docker_state" == *'"HttpsProxy":'* ]]; then
    echo "docker_daemon_proxy=set"
  else
    echo "docker_daemon_proxy=unknown"
  fi
else
  echo "docker_access=failed"
  status=1
fi

if [[ -n "$proxy_host" ]]; then
  if timeout 2 bash -c 'exec 3<>/dev/tcp/$1/$2' _ "$proxy_host" "$proxy_port" 2>/dev/null; then
    echo "proxy_tcp=reachable host=$proxy_host port=$proxy_port"
    if curl \
      --silent \
      --show-error \
      --output /dev/null \
      --head \
      --max-time 8 \
      --proxy "http://${proxy_host}:${proxy_port}" \
      https://registry-1.docker.io/v2/; then
      echo "proxy_http_connect=ok"
    else
      echo "proxy_http_connect=failed"
      status=1
    fi
  else
    echo "proxy_tcp=unreachable host=$proxy_host port=$proxy_port"
    status=1
  fi
fi

exit "$status"

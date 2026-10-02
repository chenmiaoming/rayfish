#!/usr/bin/env bash
# Regression checks for the E2E harness; no Docker daemon or cloud credentials.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "$TEST_TMP"' EXIT
# shellcheck source=lib/common.sh
source "$ROOT/tests/lib/common.sh"

check(){
  if "$@" > "$TEST_TMP/check-output" 2>&1; then
    printf 'PASS %s\n' "$*"
  else
    cat "$TEST_TMP/check-output" >&2
    printf 'FAIL %s\n' "$*" >&2
    exit 1
  fi
}

activation(){ (
  # The IPC socket appears after two failed polls. Activation must follow it.
  local attempts=0 activated=0
  sleep(){ :; }
  on(){
    case "$2" in
      'ray status') attempts=$((attempts + 1)); (( attempts >= 3 )) ;;
      'ray up') (( attempts >= 3 )) || return 1; activated=1 ;;
      'ray status --json') printf '{"active":%s}\n' "$([[ $activated == 1 ]] && echo true || echo false)" ;;
      *) return 1 ;;
    esac
  }
  activate_daemons host || return 1
  [[ $attempts == 3 && $activated == 1 && $FAILS == 0 ]]
) ; }

activation_failure(){ (
  on(){ [[ "$2" == 'ray status' ]]; }
  if activate_daemons host; then return 1; fi
  [[ $FAILS == 1 ]]
) ; }

standby_is_not_active(){ (
  on(){ return 0; }
  status_json(){ echo '{"active":false}'; }
  # Keep this failure-path check fast while still evaluating the real predicate.
  retry_until(){ shift; eval "$*"; }
  if activate_daemons host; then return 1; fi
  [[ $FAILS == 1 ]]
) ; }

network_absence(){ (
  local fixture
  status_json(){ printf '%s\n' "$fixture"; }
  fixture='{"networks":[]}'
  net_absent host priv || return 1
  fixture='{"networks":[{"name":"other"}]}'
  net_absent host priv || return 1
  for fixture in '{"networks":[{"name":"priv"}]}' '{}' 'null' '{"networks":{}}' 'invalid'; do
    if net_absent host priv; then return 1; fi
  done
  status_json(){ echo '{"networks":[]}'; return 255; }
  if net_absent host priv; then return 1; fi
) ; }

diagnostics(){ (
  # Exercise the dispatcher's actual function without provisioning a fleet.
  source <(sed -n '/^dump_diagnostics(){/,/^}/p' "$ROOT/tests/e2e.sh")
  local SERVERS="$TEST_TMP/diagnostic-servers" E2E_BACKEND=docker
  local SSH_KEY="$TEST_TMP/custom-key" scenario=closed-net
  printf 'a 1 srv-a docker\nb 2 srv-b docker\nc 3 srv-c docker\n' > "$SERVERS"
  ssh(){
    [[ "$*" == *'-n '* && "$*" == *'BatchMode=yes'* && "$*" == *"-i $SSH_KEY"* ]] || return 1
    echo "ssh $*" >> "$TEST_TMP/diagnostics"
    # A real ssh without -n would consume all the remaining server rows.
    [[ "$1" == -n ]] || cat >/dev/null
  }
  docker(){ echo "docker $*" >> "$TEST_TMP/diagnostics"; }
  dump_diagnostics >/dev/null
  [[ $(grep -c '^ssh ' "$TEST_TMP/diagnostics") == 3 ]] || return 1
  [[ $(grep -c '^docker exec ' "$TEST_TMP/diagnostics") == 3 ]]
) ; }

lifecycle(){ (
  # A sandbox copy keeps the real dispatcher and substitutes only its backends.
  local sandbox="$TEST_TMP/lifecycle"
  mkdir -p "$sandbox/tests/lib" "$sandbox/tests/e2e/closed-net"
  cp "$ROOT/tests/e2e.sh" "$sandbox/tests/e2e.sh"
  cat > "$sandbox/tests/lib/docker.sh" <<'EOF'
case "$DOCKER_ACTION" in
  provision) echo provision >> "$CALLS"; exit "${PROVISION_RC:-0}" ;;
  teardown) echo teardown >> "$CALLS"; exit "${TEARDOWN_RC:-0}" ;;
esac
EOF
  cat > "$sandbox/tests/e2e/closed-net/run.sh" <<'EOF'
echo run >> "$CALLS"
exit "${SCENARIO_RC:-0}"
EOF
  docker(){ return 0; }; export -f docker
  export CALLS="$sandbox/calls" E2E_BACKEND=docker E2E_AUTO_TEARDOWN=1
  local spec expected rc
  for spec in '42 0 0 42' '0 17 0 17' '0 17 23 17' '0 0 23 23' '0 0 0 0'; do
    read -r PROVISION_RC SCENARIO_RC TEARDOWN_RC expected <<< "$spec"
    export PROVISION_RC SCENARIO_RC TEARDOWN_RC
    : > "$CALLS"
    rc=0
    bash "$sandbox/tests/e2e.sh" closed-net run > "$sandbox/output" 2>&1 || rc=$?
    [[ $rc == "$expected" ]] || { cat "$sandbox/output"; return 1; }
    [[ $(grep -c '^teardown$' "$CALLS") == 1 ]] || return 1
    if [[ $PROVISION_RC != 0 ]]; then
      if grep -q '^run$' "$CALLS"; then return 1; fi
    else
      grep -q '^run$' "$CALLS" || return 1
    fi
  done
) ; }

udp_receivers(){ (
  local mode=normal result rc port
  port="$(python3 -c 'import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.bind(("::1",0)); print(s.getsockname()[1])')"
  on(){
    local cmd="$2"
    if [[ "$cmd" == *'sendto('* ]]; then
      case "$mode" in
        send_failure) return 1 ;;
        receiver_failure) kill "$(cat "/tmp/udp_pid_$port")"; return 0 ;;
        receive_error) touch "/tmp/udp_error_$port"; return 0 ;;
        denied|observation_failure) return 0 ;;
      esac
    fi
    if [[ "$mode" == observation_failure && "$cmd" == *'echo GOT'* ]]; then return 255; fi
    if [[ "$mode" == setup_failure && "$cmd" == *'setsid python3'* ]]; then return 1; fi
    bash -c "$cmd"
  }
  for mode in normal denied send_failure receiver_failure receive_error observation_failure setup_failure; do
    rc=0
    result="$(udp_probe local local ::1 "$port")" || rc=$?
    case "$mode" in
      normal) [[ "$result" == OPEN && $rc == 0 ]] ;;
      denied) [[ "$result" == CLOSED && $rc == 0 ]] ;;
      *) [[ "$result" == ERROR && $rc != 0 ]] ;;
    esac || { echo "$mode: got $result (exit $rc)"; return 1; }
    [[ ! -f /tmp/udp_pid_$port && ! -f /tmp/udp_ready_$port && ! -f /tmp/udp_got_$port && ! -f /tmp/udp_error_$port ]] || return 1
  done
) ; }

check activation
check activation_failure
check standby_is_not_active
check network_absence
check diagnostics
check lifecycle
check udp_receivers

#!/usr/bin/env bash
# Private invites and the inbound gate, between real hosts.
#
# Topology:
#   srv-a  coordinator, sends invites with `ray apply --invite-missing`
#   srv-b  stranger, then an older Rayfish, then a device paired to srv-c's user
#   srv-c  invite recipient and connect-request target
#
# Proves, over iroh relays and NAT rather than in-process endpoints:
#   - `inbound none` and `ray block` refuse a connect request; the sender gets no
#     request through and the recipient queues nothing
#   - `ray connect deny` refuses and blocks the requester
#   - an invite sent while the recipient is offline is queued, then delivered by
#     the retry sweep once it is back; accepting joins under the chosen hostname
#   - `inbound known` lets a peer sharing a network through and refuses a stranger
#   - declining an invitation blocks its sender
#   - a recipient on the previous release fails the invite ALPN handshake, and
#     the coordinator is told to send the code by hand
#   - blocking a paired user's identity also refuses that user's other device
#
# Reads tests/e2e/invites/.servers (written by provision). Re-runnable (resets
# rayfish state each run unless KEEP_STATE=1).
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
SERVERS="$DIR/.servers"
# shellcheck source=../../lib/common.sh
source "$ROOT/tests/lib/common.sh"

[[ -f "$SERVERS" ]] || { echo "No $SERVERS — run provision first"; exit 1; }

A="$(server_ip "$SERVERS" srv-a || true)"
B="$(server_ip "$SERVERS" srv-b || true)"
C="$(server_ip "$SERVERS" srv-c || true)"
[[ -n "$A" && -n "$B" && -n "$C" ]] || { echo "missing srv-a/b/c in $SERVERS"; exit 1; }

# The release before invite delivery existed: it has no `rayfish/invite/1` ALPN.
OLD_VERSION="${OLD_VERSION:-v0.5.9}"
OLD_URL="https://github.com/rayfish/rayfish/releases/download/$OLD_VERSION/ray-linux-x86_64"

ident(){ status_json "$1" | jq -r '.identity // empty'; }

# try_connect <from> <to-identity> : send one connect request, echo the reply.
# A refused dialer is closed at once; the timeout only guards a hang.
try_connect(){ on "$1" "timeout 40 ray connect $2" 2>&1 | strip; }

# sees_request <ip> <prefix> : exit 0 iff <ip>'s pending connect list names <prefix>.
sees_request(){ on "$1" 'ray connect' 2>/dev/null | strip | grep -q "$2"; }

# pending_invitation <ip> <net> : the id of a pending invitation to <net>, or empty.
pending_invitation(){
  on "$1" 'ray invitations --json' 2>/dev/null \
    | jq -r --arg n "$2" '.[] | select(.network == $n and .status == "pending") | .id' | head -1
}

is_blocked(){ on "$1" 'ray blocked --json' 2>/dev/null | grep -q "$2"; }

# expect_refused <from> <to-ip> <to-identity> <prefix> <label>
expect_refused(){
  local out
  out="$(try_connect "$1" "$3")"
  echo "$out" | sed 's/^/   | /'
  ! echo "$out" | grep -qi 'waiting for approval' \
    && pass "$5: sender got no approval prompt" || fail "$5: request was accepted"
  sleep 3
  ! sees_request "$2" "$4" \
    && pass "$5: nothing queued on the recipient" || fail "$5: recipient queued the request"
}

# apply_invite <alias> <identity> <net> : write a spec inviting one alias and run it.
apply_invite(){
  on "$A" "printf 'aliases:\n  $1: %s\nnetworks:\n  $3:\n    $1: {}\n' '$2' > /tmp/spec-$3.yaml"
  on "$A" "ray apply /tmp/spec-$3.yaml --invite-missing" 2>&1 | strip
}

restart_daemon(){
  on "$1" 'systemctl restart rayfish' >/dev/null 2>&1
  retry_until 60 "daemon_ready '$1'" || fail "daemon not responding on $1 after restart"
}

# ---------------------------------------------------------------------------
step "0. wait for SSH + deploy on all hosts"
wait_all_ssh "$A" "$B" "$C"
seed_known_hosts "$A" "$B" "$C"
reset_state "$A" "$B" "$C"
deploy_all "$ROOT" "$A" "$B" "$C"
on "$A" 'ray up --hostname srv-a' >/dev/null 2>&1 || true
on "$B" 'ray up --hostname srv-b' >/dev/null 2>&1 || true
on "$C" 'ray up --hostname srv-c' >/dev/null 2>&1 || true
wait_daemons "$A" "$B" "$C"

A_ID="$(ident "$A")"; B_ID="$(ident "$B")"; C_ID="$(ident "$C")"
[[ -n "$A_ID" && -n "$B_ID" && -n "$C_ID" ]] \
  && pass "read all three identities" || { fail "missing an identity"; summary; }

# ---------------------------------------------------------------------------
step "1. inbound none refuses every connect request"
on "$C" 'ray config set inbound none' 2>&1 | strip | sed 's/^/   c| /'
expect_refused "$A" "$C" "$C_ID" "${A_ID:0:8}" "inbound none"
on "$C" 'ray config set inbound anyone' >/dev/null 2>&1

# ---------------------------------------------------------------------------
step "2. ray block refuses that peer"
on "$C" "ray block $A_ID" 2>&1 | strip | sed 's/^/   c| /'
is_blocked "$C" "$A_ID" && pass "srv-a listed in srv-c's ray blocked" || fail "srv-a not in ray blocked"
expect_refused "$A" "$C" "$C_ID" "${A_ID:0:8}" "blocked peer"
on "$C" "ray unblock $A_ID" >/dev/null 2>&1

# ---------------------------------------------------------------------------
step "3. ray connect deny refuses and blocks the requester"
OUT="$(try_connect "$A" "$C_ID")"
echo "$OUT" | sed 's/^/   a| /'
echo "$OUT" | grep -qi 'waiting for approval' \
  && pass "request reaches srv-c once unblocked" || fail "unblocked request still refused"
if retry_until 30 "sees_request '$C' '${A_ID:0:8}'"; then
  pass "srv-c queued srv-a's request"
else
  fail "srv-c never queued srv-a's request"
fi
on "$C" "ray connect deny $A_ID" 2>&1 | strip | sed 's/^/   c| /'
is_blocked "$C" "$A_ID" && pass "deny blocked srv-a" || fail "deny did not block srv-a"
! sees_request "$C" "${A_ID:0:8}" && pass "denied request left the queue" || fail "denied request still queued"
on "$C" "ray unblock $A_ID" >/dev/null 2>&1

# ---------------------------------------------------------------------------
step "4. an invite to an offline recipient is delivered when it returns"
on "$C" 'systemctl stop rayfish' >/dev/null 2>&1 || true
OUT="$(apply_invite carol "$C_ID" lab)"
echo "$OUT" | sed 's/^/   a| /'
echo "$OUT" | grep -q 'unreachable; invite .* queued' \
  && pass "apply queued the invite for offline srv-c" || fail "apply did not queue the invite"
on "$C" 'systemctl start rayfish' >/dev/null 2>&1
retry_until 60 "daemon_ready '$C'" || fail "srv-c daemon did not come back"
# The sweep runs every 60s; allow three rounds.
if retry_until 180 "[[ -n \"\$(pending_invitation '$C' lab)\" ]]"; then
  pass "retry sweep delivered the invite to srv-c"
else
  fail "invite never reached srv-c"; summary
fi
INV="$(pending_invitation "$C" lab)"
on "$C" "ray invitations accept $INV --hostname srv-c" 2>&1 | strip | sed 's/^/   c| /'
if retry_until 120 "[[ \"\$(peer_online '$A' srv-c lab)\" == 1 ]]"; then
  pass "srv-c joined lab as srv-c"
else
  fail "srv-c did not join lab"
fi

# ---------------------------------------------------------------------------
step "5. inbound known admits a shared-network peer, refuses a stranger"
on "$C" 'ray config set inbound known' >/dev/null 2>&1
expect_refused "$B" "$C" "$C_ID" "${B_ID:0:8}" "stranger under inbound known"
OUT="$(try_connect "$A" "$C_ID")"
echo "$OUT" | sed 's/^/   a| /'
echo "$OUT" | grep -qi 'waiting for approval' \
  && pass "srv-a (shares lab) reaches srv-c" || fail "known peer refused under inbound known"
on "$C" 'ray config set inbound anyone' >/dev/null 2>&1

# ---------------------------------------------------------------------------
step "6. declining an invitation blocks its sender"
OUT="$(apply_invite bob "$B_ID" lab2)"
echo "$OUT" | sed 's/^/   a| /'
echo "$OUT" | grep -q 'delivered; awaiting the recipient' \
  && pass "invite delivered to srv-b" || fail "invite to srv-b not delivered"
INV="$(pending_invitation "$B" lab2)"
[[ -n "$INV" ]] && pass "srv-b has a pending invitation" || fail "srv-b has no invitation"
on "$B" "ray invitations decline $INV" 2>&1 | strip | sed 's/^/   b| /'
[[ -z "$(pending_invitation "$B" lab2)" ]] && pass "declined invitation left the inbox" || fail "invitation still pending"
is_blocked "$B" "$A_ID" && pass "decline blocked srv-a" || fail "decline did not block srv-a"
expect_refused "$A" "$B" "$B_ID" "${A_ID:0:8}" "declined sender"

# ---------------------------------------------------------------------------
step "7. an older recipient gets the code by hand instead"
on "$B" "systemctl stop rayfish; rm -rf /etc/rayfish /root/.config/rayfish; \
  curl -fsSL -o /tmp/ray-old '$OLD_URL' && install -m 755 /tmp/ray-old /usr/local/bin/ray \
  && systemctl start rayfish" >/dev/null 2>&1
retry_until 60 "daemon_ready '$B'" || fail "old srv-b daemon not responding"
on "$B" 'ray up --hostname srv-b' >/dev/null 2>&1 || true
OLD_SEEN="$(on "$B" 'ray --version' 2>&1 | strip)"
echo "   b| $OLD_SEEN"
echo "$OLD_SEEN" | grep -q "${OLD_VERSION#v}" && pass "srv-b runs $OLD_VERSION" || fail "srv-b is not on $OLD_VERSION"
# Older releases name the device's own id `endpoint` in status JSON.
B_OLD_ID="$(status_json "$B" | jq -r '.identity // .endpoint // empty')"
[[ -n "$B_OLD_ID" ]] && pass "read the older node's identity" || { fail "no identity from the older node"; summary; }
OUT="$(apply_invite dave "$B_OLD_ID" lab3)"
echo "$OUT" | sed 's/^/   a| /'
echo "$OUT" | grep -q 'older Rayfish that cannot receive invites; send them this code' \
  && pass "coordinator told to send the code by hand" || fail "older recipient not detected"
OUT="$(apply_invite dave "$B_OLD_ID" lab3)"
echo "$OUT" | sed 's/^/   a| /'
echo "$OUT" | grep -q 'send them this code' && ! echo "$OUT" | grep -q 'unreachable; invite .* queued' \
  && pass "re-apply gives the same answer and queues no retry" || fail "re-apply to the older node changed"

# Back to this build for the pairing step.
on "$B" 'systemctl stop rayfish; rm -rf /etc/rayfish /root/.config/rayfish' >/dev/null 2>&1
( cd "$ROOT" && just scp "$B" ) >/dev/null 2>&1 && pass "srv-b back on this build" || fail "redeploy srv-b"
retry_until 60 "daemon_ready '$B'" || fail "srv-b daemon not responding"
on "$B" 'ray up --hostname srv-b' >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
step "8. blocking a paired user also refuses their other device"
TICKET="$(on "$C" 'ray pair' | strip | awk -F': ' '/Pairing ticket/{print $2}' | tr -d ' ')"
PAIRED=""
for _ in 1 2 3 4 5; do
  [[ -n "$TICKET" ]] && PAIRED="$(on "$B" "ray pair $TICKET" 2>&1 | strip)"
  echo "$PAIRED" | grep -qi 'Paired successfully' && break
  sleep 3
  TICKET="$(on "$C" 'ray pair' | strip | awk -F': ' '/Pairing ticket/{print $2}' | tr -d ' ')"
done
echo "$PAIRED" | grep -qi 'Paired successfully' && pass "srv-b paired to srv-c's user" || { fail "pairing failed"; summary; }
# The running daemon only loads a new device cert at start.
restart_daemon "$B"
B_EP="$(status_json "$B" | jq -r '.endpoint // empty')"
CODE="$(mint_invite "$A" lab srv-b)"
[[ -n "$CODE" ]] && pass "minted a lab invite for srv-b" || { fail "could not mint an invite"; summary; }
on "$B" "ray join $CODE" 2>&1 | strip | sed 's/^/   b| /'
if retry_until 120 "[[ \"\$(peer_online '$A' srv-b lab)\" == 1 ]]"; then
  pass "srv-b joined lab"
else
  fail "srv-b did not join lab"; summary
fi
on "$A" "ray block $C_ID" 2>&1 | strip | sed 's/^/   a| /'
expect_refused "$B" "$A" "$A_ID" "${B_EP:0:8}\|${C_ID:0:8}" "device of a blocked user"
on "$A" "ray unblock $C_ID" >/dev/null 2>&1
OUT="$(try_connect "$B" "$A_ID")"
echo "$OUT" | sed 's/^/   b| /'
echo "$OUT" | grep -qi 'waiting for approval' \
  && pass "the same device reaches srv-a once the user is unblocked" || fail "device still refused after unblock"

# ---------------------------------------------------------------------------
summary

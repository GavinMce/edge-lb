#!/usr/bin/env bash
# End-to-end test of managed WireGuard with real kernels, real systemd and real packets.
#
#   client ──► edge (public) ═══ WireGuard ═══ gateway ──► target (home LAN, reachable ONLY through the tunnel)
#
# Needs Docker (privileged containers, so the kernel's WireGuard is used) and a static binary:
#   CC_x86_64_unknown_linux_musl=gcc cargo build --target x86_64-unknown-linux-musl
#   tests/e2e/wireguard.sh [path/to/edge-lbd]
#
# Everything is driven the way a user would: the controller API creates the edge and the site, and the
# gateway is installed by running the exact command the controller hands out. KEEP=1 leaves containers up.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${1:-$HERE/../../target/x86_64-unknown-linux-musl/debug/edge-lbd}
P=elb-e2e
IMG=$P-img
WAN=$P-wan LAN=$P-lan
WAN_NET=172.29.77.0/24 LAN_NET=192.168.77.0/24
CTL_IP=172.29.77.10 EDGE_IP=172.29.77.20 GW_WAN_IP=172.29.77.30 CLIENT_IP=172.29.77.40
GW_LAN_IP=192.168.77.2 TARGET_IP=192.168.77.10
PASS=0 FAIL=0

c() { docker exec "$@"; }
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
check_not() { local d=$1; shift; if "$@" >/dev/null 2>&1; then bad "$d"; else ok "$d"; fi; }

# wait_until "description" seconds command...
wait_until() {
  local d=$1 t=$2; shift 2
  local end=$((SECONDS + t))
  while [ $SECONDS -lt $end ]; do "$@" >/dev/null 2>&1 && { ok "$d"; return 0; }; sleep 2; done
  bad "$d (timed out after ${t}s)"; return 1
}

api() { c $P-ctl python3 /opt/api.py "$@"; }
pyget() { python3 -c 'import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }
status_is() { [ "$(api GET /api/status | pyget "$1")" = "True" ]; }

cleanup() {
  if [ "${KEEP:-}" = 1 ]; then echo "KEEP=1: leaving containers ($P-*) and networks up"; return; fi
  docker rm -f $P-ctl $P-edge $P-gw $P-target $P-client >/dev/null 2>&1
  docker network rm $WAN $LAN >/dev/null 2>&1
}
diagnostics() {
  say "diagnostics"
  echo "--- controller log"; c $P-ctl tail -n 30 /var/log/ctl.log 2>&1
  echo "--- edge status"; api GET /api/status 2>&1 | python3 -c 'import sys,json; d=json.load(sys.stdin); [print(e["id"], e["status"], e.get("error"), [l["msg"] for l in e["log"][-6:]]) for e in d["edges"]]; print(json.dumps(d["sites"], indent=1))' 2>&1
  echo "--- edge wg"; c $P-edge wg show 2>&1 | head -20; c $P-edge journalctl -u edge-lb-wg -n 15 --no-pager 2>&1 | tail -15
  echo "--- gateway wg"; c $P-gw wg show 2>&1 | head -20; c $P-gw journalctl -u edge-lb-gateway -n 20 --no-pager 2>&1 | tail -20
}
trap 'cleanup' EXIT

[ -x "$BIN" ] || { echo "binary not found: $BIN (see the header of this script)"; exit 2; }
docker info >/dev/null 2>&1 || { echo "docker is not available"; exit 2; }
cleanup

# ------------------------------------------------------------------------------------------------
say "Build the test image and the network"
docker build -q -t $IMG "$HERE" >/dev/null || { echo "image build failed"; exit 2; }
docker network create --subnet $WAN_NET $WAN >/dev/null
docker network create --internal --subnet $LAN_NET $LAN >/dev/null   # no way out: only the gateway bridges it

sysd() { # name network ip
  docker run -d --name "$1" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /run/lock --network "$2" --ip "$3" $IMG >/dev/null
}
sysd $P-edge $WAN $EDGE_IP
sysd $P-gw $LAN $GW_LAN_IP
docker network connect --ip $GW_WAN_IP $WAN $P-gw
docker run -d --name $P-ctl --network $WAN --ip $CTL_IP $IMG sleep infinity >/dev/null
docker run -d --name $P-client --network $WAN --ip $CLIENT_IP $IMG sleep infinity >/dev/null
docker run -d --name $P-target --network $LAN --ip $TARGET_IP $IMG sh -c \
  'mkdir -p /srv && echo "hello from the home LAN" > /srv/index.html && exec python3 -m http.server 8080 --directory /srv' >/dev/null
wait_until "edge systemd and sshd are up" 60 c $P-edge systemctl is-active ssh
wait_until "gateway systemd is up" 60 c $P-gw systemctl is-active multi-user.target

say "Sanity: the LAN really is unreachable except through the gateway"
check_not "the public edge can't reach the home LAN directly" c $P-edge curl -sS -m 3 http://$TARGET_IP:8080/
check_not "the client can't reach the home LAN directly" c $P-client curl -sS -m 3 http://$TARGET_IP:8080/
check "the gateway itself can reach the LAN" c $P-gw python3 -c "import urllib.request as u; u.urlopen('http://$TARGET_IP:8080/', timeout=3)"

# ------------------------------------------------------------------------------------------------
say "Start the controller (with the gateway listener)"
docker cp "$BIN" $P-ctl:/usr/local/bin/edge-lbd
docker cp "$HERE/api.py" $P-ctl:/opt/api.py
c $P-ctl chmod +x /usr/local/bin/edge-lbd
start_controller() {
  docker exec -d $P-ctl sh -c "exec edge-lbd controller --data-dir /var/lib/ctl --listen 0.0.0.0:8080 --allow-public \
    --gateway-listen 0.0.0.0:7444 --gateway-host $CTL_IP >> /var/log/ctl.log 2>&1"
}
start_controller
wait_until "controller is up" 30 c $P-ctl curl -fsS http://127.0.0.1:8080/healthz
CODE=$(c $P-ctl cat /var/lib/ctl/setup-code | tr -d '\n')
api POST /api/setup "{\"setup_code\":\"$CODE\",\"username\":\"admin\",\"password\":\"correct horse battery staple\"}" >/dev/null
api POST /api/login '{"username":"admin","password":"correct horse battery staple"}' >/dev/null
check "admin signed in" api GET /api/status
gw_listener_ok() { [ "$(api GET /api/status | pyget 'd["gateway_listener"]')" = "$CTL_IP:7444" ]; }
check "the gateway listener is advertised" gw_listener_ok

# ------------------------------------------------------------------------------------------------
say "Adopt the edge over SSH (installs the binary, WireGuard and the root applier)"
KEY=$(api GET /api/ssh-key | pyget 'd["public_key"]')
c $P-edge sh -c "echo '$KEY' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
api POST /api/edges "{\"name\":\"edge1\",\"provider\":{\"kind\":\"manual\"},\"ip\":\"$EDGE_IP\"}" >/dev/null
wait_until "edge is healthy" 240 status_is 'd["edges"][0]["status"]=="healthy"' || diagnostics
check "the edge reported its WireGuard public key" status_is 'len(d["edges"][0].get("wg_public_key") or "")==44'
check "the edge got a tunnel address" status_is 'str(d["edges"][0].get("tunnel_ip")).startswith("10.100.0.")'
check "the root applier unit is running on the edge" c $P-edge systemctl is-active edge-lb-wg
check "the edge process itself has no network-admin capability" c $P-edge sh -c 'systemctl show -p CapabilityBoundingSet --value edge-lbd | grep -qv net_admin'

# ------------------------------------------------------------------------------------------------
say "Create the site and enrol a gateway with the exact command the UI shows"
api POST /api/sites "{\"name\":\"home\",\"lan_cidrs\":[\"$LAN_NET\"]}" >/dev/null
CMD=$(api POST /api/sites/home/enrol | pyget 'd["command"]')
echo "  command: ${CMD:0:110}…"
pinned() { [[ $CMD == *--pinnedpubkey* ]]; }
check "the command pins the controller's key" pinned
c $P-gw sh -c "$CMD" 2>&1 | sed 's/^/    gw: /'
wait_until "the gateway shows up enrolled and online" 60 status_is 'd["sites"][0]["gateway"]["online"] and d["sites"][0]["gateway"]["enrolled"]' || diagnostics
wait_until "the controller sees the tunnel up (real handshake)" 90 status_is 'd["sites"][0]["gateway"]["tunnels"][0]["up"]==True' || diagnostics
check "the gateway is in sync with the controller" status_is 'd["sites"][0]["gateway"]["in_sync"]==True'
check_not "re-using the enrolment command fails (token is single-use)" c $P-gw bash -c "set -o pipefail; $CMD"
check "wg-edge exists on the edge with the gateway as its peer" c $P-edge sh -c 'wg show wg-edge peers | grep -q .'
check "the edge's route to the LAN goes into the tunnel" c $P-edge sh -c "ip -4 route get $TARGET_IP | grep -q wg-edge"
check "the gateway has the forwarding firewall (own table, not a flushed ruleset)" c $P-gw nft list table inet edge_lb_gw
GW_TUN=$(api GET /api/status | pyget 'd["sites"][0]["gateway"]["tunnel_ip"]')

# ------------------------------------------------------------------------------------------------
say "A route to a LAN address, through the tunnel"
api POST /api/routes "{\"name\":\"app\",\"listen\":{\"ip\":\"0.0.0.0\",\"port\":8443},\"domains\":[\"app.test\"],
  \"targets\":[{\"address\":\"$TARGET_IP\",\"port\":8080}],\"site\":\"home\"}" >/dev/null
fetch() { c $P-client curl -fsS -m 5 -H 'Host: app.test' http://$EDGE_IP:8443/; }
wait_until "the route is live on the edge" 60 fetch
page_ok() { [ "$(fetch)" = 'hello from the home LAN' ]; }
check "client → edge → tunnel → gateway → LAN target returns the LAN's page" page_ok
check_not "a wrong hostname doesn't reach the target" c $P-client curl -fsS -m 3 -H 'Host: other.test' http://$EDGE_IP:8443/
check_not "the controller rejects an un-sited route into the LAN" api POST /api/routes "{\"name\":\"sneaky\",\"listen\":{\"ip\":\"0.0.0.0\",\"port\":8444},\"domains\":[\"s.test\"],\"targets\":[{\"address\":\"$TARGET_IP\",\"port\":8080}]}"

# ------------------------------------------------------------------------------------------------
say "A compromised edge can reach only the declared LAN (gateway firewall)"
check "control: the edge can reach the controller's UI port normally" c $P-edge curl -fsS -m 3 -o /dev/null http://$CTL_IP:8080/healthz
GWKEY=$(c $P-edge wg show wg-edge peers | head -1)
# Pretend the edge is hostile: widen its own idea of where the gateway can take it, and route there.
c $P-edge wg set wg-edge peer "$GWKEY" allowed-ips "$GW_TUN/32,$LAN_NET,$CTL_IP/32"
c $P-edge ip route add $CTL_IP/32 dev wg-edge
check_not "...but sent through the tunnel, the gateway drops traffic to anywhere but the LAN" c $P-edge curl -fsS -m 4 -o /dev/null http://$CTL_IP:8080/healthz
check "the declared LAN is still reachable the same way" c $P-edge curl -fsS -m 4 -o /dev/null http://$TARGET_IP:8080/
c $P-edge ip route del $CTL_IP/32 dev wg-edge
c $P-edge wg set wg-edge peer "$GWKEY" allowed-ips "$GW_TUN/32,$LAN_NET"
check "the edge may ping the gateway over the tunnel" c $P-edge ping -c1 -W2 "$GW_TUN"
check "control: the gateway's sshd answers on its normal address" c $P-edge nc -z -w3 $GW_WAN_IP 22
check_not "...but not to the edge over the tunnel (input is closed)" c $P-edge nc -z -w3 "$GW_TUN" 22

# ------------------------------------------------------------------------------------------------
say "The data path doesn't depend on the controller (fail-static)"
c $P-ctl pkill edge-lbd
sleep 2
check_not "controller is down" c $P-ctl curl -fsS -m 2 http://127.0.0.1:8080/healthz
check "traffic still flows with the controller down" fetch
start_controller
wait_until "controller is back" 30 c $P-ctl curl -fsS http://127.0.0.1:8080/healthz
api POST /api/login '{"username":"admin","password":"correct horse battery staple"}' >/dev/null
wait_until "the gateway reconnects and reports in sync" 60 status_is 'd["sites"][0]["gateway"]["online"] and d["sites"][0]["gateway"]["in_sync"]==True'

say "Reboots restore the tunnel without anyone's help"
docker restart $P-edge >/dev/null
wait_until "edge is back and wg-edge was re-created from its saved state" 120 c $P-edge sh -c 'wg show wg-edge peers | grep -q .'
wait_until "traffic flows again after the EDGE reboots" 90 fetch
docker restart $P-gw >/dev/null
wait_until "gateway is back with its tunnel" 120 c $P-gw sh -c 'wg show wg-edge peers | grep -q .'
wait_until "traffic flows again after the GATEWAY reboots" 90 fetch

# ------------------------------------------------------------------------------------------------
say "Removing the route and site tears the tunnel down on the edge"
api DELETE /api/routes/app >/dev/null
check "a site can't be deleted while routes use it (checked earlier); now it can" api DELETE /api/sites/home
no_wg_edge() { ! c $P-edge ip link show wg-edge; }
wait_until "the edge removed wg-edge" 60 no_wg_edge
check_not "the LAN is no longer reachable from the edge" c $P-edge curl -sS -m 3 http://$TARGET_IP:8080/

say "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || { diagnostics; exit 1; }

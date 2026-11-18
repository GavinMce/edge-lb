#!/bin/sh
# edge-lb controller installer for a Linux server with systemd.
#
#   curl -fsSL https://github.com/@REPO@/releases/latest/download/install-controller.sh | sudo sh -s -- [options]
#
# Downloads the release's static binaries (checksum-verified), installs the controller as the
# unprivileged user "edge-lb" under a sandboxed systemd unit, starts it, and prints the one-time
# setup code. Run it again to upgrade or to change options; your data is kept.
#
# The controller serves its web UI on a private address (default 127.0.0.1:8080). It never exposes
# it publicly by itself: reach it through an SSH tunnel, a private network address, or your own
# TLS reverse proxy (see --tls-proxy).
#
# Options
#   --listen ADDR:PORT        where the web UI listens (default 127.0.0.1:8080; private addresses only)
#   --tls-proxy               a TLS reverse proxy on this machine fronts the UI: mark cookies Secure
#   --gateway-listen A:P      accept WireGuard gateways here (e.g. 0.0.0.0:7444); needs --gateway-host
#   --gateway-host HOST[:P]   the name or IPv4 address gateways use to reach this machine
#   --version TAG             install this release instead of the one this script came from
#   --release-base URL        fetch release files from URL (https:// or file://) instead of GitHub
#   --from DIR                use DIR/edge-lbd-x86_64 and DIR/edge-lbd-aarch64 instead of downloading
#   --this-arch-only          don't fetch the other CPU's build (it is what lets this controller
#                             install edges of either kind)
#   --uninstall [--purge]     remove the service and program; --purge also deletes data and the user
#   --stage DIR               testing: install under DIR, no root, no systemd

VERSION="@VERSION@"
REPO="@REPO@"

main() {
  set -eu

  NAME=edge-lb-controller
  SVC_USER=edge-lb
  BIN_PATH=/usr/local/bin/edge-lb-controller
  LIB=/usr/local/lib/edge-lb
  UNIT_PATH=/etc/systemd/system/$NAME.service
  DATA=/var/lib/edge-lb-controller

  LISTEN=127.0.0.1:8080
  TLS_PROXY=0
  GW_LISTEN=
  GW_HOST=
  RELEASE_BASE=
  FROM=
  THIS_ARCH_ONLY=0
  UNINSTALL=0
  PURGE=0
  STAGE=

  while [ $# -gt 0 ]; do
    case $1 in
      --listen) need_arg "$@"; LISTEN=$2; shift 2 ;;
      --tls-proxy) TLS_PROXY=1; shift ;;
      --gateway-listen) need_arg "$@"; GW_LISTEN=$2; shift 2 ;;
      --gateway-host) need_arg "$@"; GW_HOST=$2; shift 2 ;;
      --version) need_arg "$@"; VERSION=$2; shift 2 ;;
      --release-base) need_arg "$@"; RELEASE_BASE=$2; shift 2 ;;
      --from) need_arg "$@"; FROM=$2; shift 2 ;;
      --this-arch-only) THIS_ARCH_ONLY=1; shift ;;
      --uninstall) UNINSTALL=1; shift ;;
      --purge) PURGE=1; shift ;;
      --stage) need_arg "$@"; STAGE=$2; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done

  # Everything below is validated before anything is written, because these values end up in a
  # systemd unit that runs on a real machine.
  is_addr_port "$LISTEN" || die "--listen must look like 127.0.0.1:8080"
  if [ -n "$GW_LISTEN$GW_HOST" ]; then
    [ -n "$GW_LISTEN" ] && [ -n "$GW_HOST" ] || die "--gateway-listen and --gateway-host go together"
    is_addr_port "$GW_LISTEN" || die "--gateway-listen must look like 0.0.0.0:7444"
    is_host "$GW_HOST" || die "--gateway-host must be a host name or IPv4 address"
  fi
  [ -z "$RELEASE_BASE" ] || is_release_base "$RELEASE_BASE" || die "--release-base must be an https:// or file:// URL"
  [ -z "$FROM" ] || [ -d "$FROM" ] || die "--from: $FROM is not a directory"
  [ -z "$STAGE" ] || [ -d "$STAGE" ] || die "--stage: $STAGE is not a directory"

  R=$STAGE   # prefix for every system path (empty on a real install)

  if [ -z "$STAGE" ]; then
    [ "$(id -u)" -eq 0 ] || die "run this as root (put sudo before 'sh')"
    command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || die "systemd is required"
  fi

  if [ "$UNINSTALL" -eq 1 ]; then
    uninstall
    return 0
  fi

  ARCH=$(this_arch)
  if [ -z "$FROM" ]; then
    is_version "$VERSION" || die "this copy of the installer isn't from a release: pass --version TAG (or --from DIR)"
    [ -n "$RELEASE_BASE" ] || RELEASE_BASE=https://github.com/$REPO/releases/download/$VERSION
    command -v curl >/dev/null 2>&1 || die "curl is required"
  fi

  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT INT TERM

  say "==> Getting the programs"
  ARCHS=$ARCH
  if [ "$THIS_ARCH_ONLY" -eq 0 ]; then ARCHS="x86_64 aarch64"; fi
  for a in $ARCHS; do
    get_binary "$a" || { [ "$a" = "$ARCH" ] && die "no build for this machine's CPU ($ARCH) in ${FROM:-$RELEASE_BASE}"; continue; }
    eval "BIN_$a=\$GOT"
  done
  eval "THIS_BIN=\${BIN_$ARCH:-}"
  [ -n "$THIS_BIN" ] || die "no build for this machine's CPU ($ARCH)"
  if [ -z "$STAGE" ]; then
    "$THIS_BIN" controller --help >/dev/null 2>&1 </dev/null || die "the downloaded program does not run on this machine"
  fi

  [ -z "$STAGE" ] && ensure_packages

  say "==> Installing"
  install -d -m 0755 "$R$LIB" "$R$LIB/agents" "$R/usr/local/bin" "$R/etc/systemd/system"
  put "$THIS_BIN" "$R$BIN_PATH" 0755
  for a in $ARCHS; do
    eval "b=\${BIN_$a:-}"
    [ -z "$b" ] || put "$b" "$R$LIB/agents/edge-lbd-$a" 0755
  done

  if [ -z "$STAGE" ] && ! id "$SVC_USER" >/dev/null 2>&1; then
    nologin=/usr/sbin/nologin; [ -x "$nologin" ] || nologin=/sbin/nologin
    useradd --system --user-group --home-dir "$DATA" --no-create-home --shell "$nologin" "$SVC_USER"
  fi

  write_unit
  [ -n "$STAGE" ] && { say "staged under $STAGE"; return 0; }

  systemctl daemon-reload
  systemctl enable "$NAME" >/dev/null 2>&1
  systemctl restart "$NAME"

  say "==> Waiting for it to come up"
  health=$LISTEN
  case $health in 0.0.0.0:*) health=127.0.0.1:${health#0.0.0.0:} ;; "[::]:"*) health="[::1]:${health#"[::]:"}" ;; esac
  i=0
  while [ "$i" -lt 30 ]; do
    if systemctl is-active --quiet "$NAME" && curl -fsS -o /dev/null "http://$health/healthz" 2>/dev/null; then break; fi
    i=$((i + 1)); sleep 1
  done
  if ! systemctl is-active --quiet "$NAME" || [ "$i" -ge 30 ]; then
    journalctl -u "$NAME" -n 15 --no-pager 2>/dev/null || true
    die "the controller did not start (log above; also: journalctl -u $NAME)"
  fi

  summary
}

# ---- helpers ------------------------------------------------------------------------------------

say() { printf '%s\n' "$*"; }
die() { printf 'edge-lb: %s\n' "$*" >&2; exit 1; }
need_arg() { [ $# -ge 2 ] || die "$1 needs a value"; }
usage() {
  cat <<'EOF'
edge-lb controller installer (Linux, systemd). Run as root:
  curl -fsSL <release-url>/install-controller.sh | sudo sh -s -- [options]

  --listen ADDR:PORT        where the web UI listens (default 127.0.0.1:8080; private addresses only)
  --tls-proxy               a TLS reverse proxy on this machine fronts the UI: mark cookies Secure
  --gateway-listen A:P      accept WireGuard gateways here (e.g. 0.0.0.0:7444); needs --gateway-host
  --gateway-host HOST[:P]   the name or IPv4 address gateways use to reach this machine
  --version TAG             install this release instead of the one this script came from
  --release-base URL        fetch release files from URL (https:// or file://) instead of GitHub
  --from DIR                use DIR/edge-lbd-x86_64 and DIR/edge-lbd-aarch64 instead of downloading
  --this-arch-only          don't fetch the other CPU's build
  --uninstall [--purge]     remove the service and program; --purge also deletes data and the user
  --stage DIR               testing: install under DIR, no root, no systemd
EOF
}

# grep matches line by line, so "ok\nExecStartPre=..." would pass a pattern for "ok" and then add a
# line to the systemd unit. Every value is refused if it has more than one line.
one_line() {
  case $1 in
    *'
'*) return 1 ;;
  esac
}

is_addr_port() {
  one_line "$1" && printf '%s' "$1" | grep -Eq '^([0-9]{1,3}(\.[0-9]{1,3}){3}|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}$' || return 1
  p=${1##*:}
  [ "$p" -ge 1 ] && [ "$p" -le 65535 ]
}
is_host() { one_line "$1" && printf '%s' "$1" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:[0-9]{1,5})?$'; }
is_version() { one_line "$1" && printf '%s' "$1" | grep -Eq '^v?[0-9][0-9A-Za-z.+_-]{0,40}$'; }
is_release_base() { one_line "$1" && printf '%s' "$1" | grep -Eq '^(https|file)://[A-Za-z0-9._~:/%@+=-]+$'; }

this_arch() {
  case $(uname -m) in
    x86_64|amd64) printf x86_64 ;;
    aarch64|arm64) printf aarch64 ;;
    *) die "unsupported CPU: $(uname -m) (builds exist for x86_64 and aarch64)" ;;
  esac
}

# get_binary ARCH: sets GOT to a file holding that build, or returns 1 if there is none.
get_binary() {
  arch=$1
  if [ -n "$FROM" ]; then
    [ -f "$FROM/edge-lbd-$arch" ] || return 1
    GOT=$FROM/edge-lbd-$arch
    return 0
  fi
  name=edge-lbd-$VERSION-linux-$arch
  proto='=https'; case $RELEASE_BASE in file://*) proto='=https,file' ;; esac
  curl -fsSL --proto "$proto" --retry 3 --connect-timeout 15 -o "$WORK/$name.tar.gz" "$RELEASE_BASE/$name.tar.gz" </dev/null 2>/dev/null || return 1
  curl -fsSL --proto "$proto" --retry 3 --connect-timeout 15 -o "$WORK/$name.tar.gz.sha256" "$RELEASE_BASE/$name.tar.gz.sha256" </dev/null 2>/dev/null \
    || die "could not fetch the checksum for $name.tar.gz"
  (cd "$WORK" && sha256sum -c "$name.tar.gz.sha256" >/dev/null 2>&1 </dev/null) || die "checksum mismatch for $name.tar.gz: nothing was installed"
  tar -xzf "$WORK/$name.tar.gz" -C "$WORK" "$name/edge-lbd" </dev/null || die "could not unpack $name.tar.gz"
  GOT=$WORK/$name/edge-lbd
}

# put SRC DEST MODE: replace DEST atomically.
put() {
  install -m "$3" "$1" "$2.new"
  mv -f "$2.new" "$2"
}

ensure_packages() {
  have_ssh=1; command -v ssh >/dev/null 2>&1 && command -v ssh-keygen >/dev/null 2>&1 || have_ssh=0
  have_ca=1; [ -e /etc/ssl/certs/ca-certificates.crt ] || [ -e /etc/pki/tls/certs/ca-bundle.crt ] || have_ca=0
  [ "$have_ssh" -eq 1 ] && [ "$have_ca" -eq 1 ] && return 0
  say "==> Installing the OpenSSH client (the controller uses it to reach your machines)"
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq </dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-client ca-certificates </dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q openssh-clients ca-certificates </dev/null
  else
    die "install an OpenSSH client (ssh, ssh-keygen) and CA certificates, then run this again"
  fi
}

write_unit() {
  args="controller --listen $LISTEN --data-dir $DATA --agents-dir $LIB/agents"
  [ -z "$GW_LISTEN" ] || args="$args --gateway-listen $GW_LISTEN --gateway-host $GW_HOST"
  [ "$TLS_PROXY" -eq 0 ] || args="$args --secure-cookies"
  cat > "$R$UNIT_PATH.new" <<UNIT
[Unit]
Description=edge-lb controller (web UI and API)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN_PATH $args
User=$SVC_USER
Group=$SVC_USER
Environment=HOME=$DATA
Restart=on-failure
RestartSec=2
StateDirectory=edge-lb-controller
StateDirectoryMode=0700
UMask=0077
CapabilityBoundingSet=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
  mv -f "$R$UNIT_PATH.new" "$R$UNIT_PATH"
}

summary() {
  code=
  [ -r "$DATA/setup-code" ] && code=$(cat "$DATA/setup-code")
  say ""
  say "edge-lb controller $NAME is running (data in $DATA)."
  if [ -n "$code" ]; then
    say ""
    say "  SETUP CODE: $code"
    say "  Enter it on the controller's first page to create the administrator account."
  else
    say "  The administrator account already exists: sign in as before."
  fi
  say ""
  case $LISTEN in
    127.*|"[::1]:"*)
      if [ "$TLS_PROXY" -eq 1 ]; then
        say "TLS reverse proxy: point it at http://$LISTEN. With Caddy, for example:"
        say ""
        say "    your.domain.example {"
        say "        reverse_proxy $LISTEN"
        say "    }"
      else
        say "The UI listens only on this machine. From your own computer, open an SSH tunnel:"
        say ""
        say "    ssh -N -L 8081:$LISTEN USER@THIS-SERVER"
        say ""
        say "then connect to http://127.0.0.1:8081"
      fi ;;
    *) say "The UI is at http://$LISTEN: allow that port only from your private network." ;;
  esac
  if [ -n "$GW_LISTEN" ]; then
    say ""
    say "Gateways connect to $GW_HOST: allow inbound TCP ${GW_LISTEN##*:} on this machine's firewall."
  fi
  say ""
  say "This machine must be able to reach your edges (SSH, and TCP 7443) and, if you use them,"
  say "the Hetzner and Cloudflare APIs. Upgrade or change options: run the same command again."
  say "Remove: the same command with --uninstall (add --purge to delete data too)."
}

uninstall() {
  say "==> Removing the edge-lb controller"
  if [ -z "$STAGE" ]; then
    systemctl disable --now "$NAME" >/dev/null 2>&1 || true
  fi
  rm -f "$R$UNIT_PATH" "$R$BIN_PATH"
  rm -rf "$R$LIB"
  [ -n "$STAGE" ] || systemctl daemon-reload
  if [ "$PURGE" -eq 1 ]; then
    rm -rf "$R$DATA"
    [ -n "$STAGE" ] || ! id "$SVC_USER" >/dev/null 2>&1 || userdel "$SVC_USER" >/dev/null 2>&1 || true
    say "Removed, including data and the $SVC_USER user."
  else
    say "Removed. Your data is still in $DATA (use --purge to delete it)."
  fi
}

main "$@"

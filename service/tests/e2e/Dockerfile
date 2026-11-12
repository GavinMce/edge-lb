# A tiny stand-in for "a fresh Debian VPS": systemd, sshd, and nothing WireGuard-related, so the
# installers have to bring in wireguard-tools themselves (the real apt path).
FROM debian:12-slim
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      systemd systemd-sysv openssh-server openssh-client sudo curl ca-certificates \
      iproute2 iputils-ping netcat-openbsd procps python3 kmod \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /root/.ssh && chmod 700 /root/.ssh \
 && printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\n' > /etc/ssh/sshd_config.d/e2e.conf \
 && systemctl enable ssh \
 && systemctl mask systemd-logind getty.target console-getty.service systemd-udev-trigger.service
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]

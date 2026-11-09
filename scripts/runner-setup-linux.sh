#!/bin/sh
# Sets up a ucanrun runner on Linux: its own user, the ucr binary and a
# systemd service. Run as root:  sudo sh runner-setup-linux.sh ./ucr
#
# Commands that need root go through sudo with the runner user's password,
# which only ucanrun holds. Nothing here gives the runner passwordless root.
set -eu

BIN=${1:-}
RUNNER_USER=${RUNNER_USER:-ucr-runner}
DIR=/var/lib/$RUNNER_USER
# Programs the runner user may start as root through sudo, space separated.
# Empty: no sudo rule is written.
SUDO_CMDS=${SUDO_CMDS:-}

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo sh $0 PATH_TO_UCR" >&2
  exit 1
fi
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  echo "usage: sudo sh $0 PATH_TO_UCR" >&2
  exit 1
fi

install -m 0755 "$BIN" /usr/local/bin/ucr

if ! id -u "$RUNNER_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$DIR" --create-home --shell /usr/sbin/nologin "$RUNNER_USER"
fi
mkdir -p "$DIR"
chown "$RUNNER_USER:" "$DIR"
chmod 700 "$DIR"

if [ -n "$SUDO_CMDS" ]; then
  list=""
  for c in $SUDO_CMDS; do
    case "$c" in
      /*) ;;
      *) echo "sudo commands must be absolute paths: $c" >&2; exit 1 ;;
    esac
    list="${list:+$list, }$c"
  done
  rule=/etc/sudoers.d/$RUNNER_USER
  tmp=$(mktemp)
  # A password is always asked; the runner sends the one ucanrun holds.
  printf 'Defaults:%s !lecture, passwd_tries=1\n%s ALL=(root) %s\n' "$RUNNER_USER" "$RUNNER_USER" "$list" > "$tmp"
  visudo -cf "$tmp" >/dev/null
  install -m 0440 "$tmp" "$rule"
  rm -f "$tmp"
  echo "sudo rule: $rule"
  # A random password that only ucanrun will hold. Shown once, here.
  pw=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | cut -c1-28)
  echo "$RUNNER_USER:$pw" | chpasswd
  echo
  echo "Password of $RUNNER_USER (save it in ucanrun now, then clear the screen):"
  echo "  $pw"
  echo "Secret settings: allow in commands, always ask for TOTP."
  unset pw
fi

cat > /etc/systemd/system/ucr-runner.service <<UNIT
[Unit]
Description=ucanrun runner
After=network-online.target
Wants=network-online.target

[Service]
User=$RUNNER_USER
Environment=UCANRUN_RUNNER_DIR=$DIR
ExecStart=/usr/local/bin/ucr runner serve
Restart=always
RestartSec=5
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload

cat <<NEXT

Installed. Next:

1. With SUDO_CMDS set, the password printed above goes into ucanrun as a
   secret; agents then pass it as sudo: {{secret:NAME}}.
2. Create a pairing code in ucanrun (Overview, Devices and rights, Add runner),
   then enroll as the runner user:
     sudo -u $RUNNER_USER UCANRUN_RUNNER_DIR=$DIR ucr runner enroll URL CODE --name NAME
3. List the programs it may run in $DIR/runner.toml.
4. Start it:
     systemctl enable --now ucr-runner
     journalctl -u ucr-runner -f
NEXT

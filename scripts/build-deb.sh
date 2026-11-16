#!/bin/sh
# Builds the Debian package of ucr from a release binary.
#   sh scripts/build-deb.sh VERSION ARCH BINARY OUT_DIR    (ARCH: amd64 or arm64)
# It installs /usr/bin/ucr, the ucr-runner service (off until you enable it),
# the ucr-runner user and /var/lib/ucr-runner. Upgrades restart a running
# runner. For sudo rules: sudo SUDO_CMDS="..." sh /usr/share/ucr/runner-setup-linux.sh
set -eu
VERSION=$1 ARCH=$2 BIN=$3 OUT=$4
case "$ARCH" in amd64|arm64) ;; *) echo "ARCH must be amd64 or arm64" >&2; exit 2 ;; esac
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(mktemp -d)
chmod 755 "$root"
trap 'rm -rf "$root"' EXIT
install -D -m 0755 "$BIN" "$root/usr/bin/ucr"
install -D -m 0644 "$here/packaging/deb/ucr-runner.service" "$root/usr/lib/systemd/system/ucr-runner.service"
install -D -m 0755 "$here/scripts/runner-setup-linux.sh" "$root/usr/share/ucr/runner-setup-linux.sh"
install -D -m 0644 "$here/LICENSE" "$root/usr/share/doc/ucr/copyright"
mkdir -p "$root/DEBIAN"
for f in postinst prerm postrm; do install -m 0755 "$here/packaging/deb/$f" "$root/DEBIAN/$f"; done
size=$(du -sk "$root/usr" | awk '{s+=$1} END {print s}')
cat > "$root/DEBIAN/control" <<CONTROL
Package: ucr
Version: $VERSION
Architecture: $ARCH
Maintainer: huydnd <huydnd@users.noreply.github.com>
Installed-Size: $size
Recommends: sudo
Section: utils
Priority: optional
Homepage: https://github.com/huydnd/ucanrun
Description: ucanrun client: the agent side and the runner
 ucr lets AI agents ask a ucanrun server to run calls and commands that use
 your secrets, after you approve them; the agent never sees a secret. As a
 runner, it takes approved jobs from the server and runs them on this machine
 under its own user, limited to the programs listed in runner.toml.
CONTROL
mkdir -p "$OUT"
dpkg-deb --root-owner-group -Zxz --build "$root" "$OUT/ucr_${VERSION}_${ARCH}.deb" >/dev/null
echo "$OUT/ucr_${VERSION}_${ARCH}.deb"

# Inside a runner container: a user r whose sudo password only ucanrun holds.
set -e
apk add -q sudo curl >/dev/null
adduser -D -h /home/r r
echo "r:lab-sudo-PASS-7319" | chpasswd 2>/dev/null
printf 'Defaults:r !lecture, passwd_tries=1\nr ALL=(root) /usr/bin/id\n' > /etc/sudoers.d/r
chmod 440 /etc/sudoers.d/r
install -m 755 /w/ucr /usr/local/bin/ucr

#!/bin/sh
# ScamStop installer. Everything it needs is inside this file: no internet
# downloads except your distribution's own Redis/OpenSSL packages.
#
#   sudo sh scamstop-installer-VERSION-linux-x86_64.run              install or upgrade
#   sudo sh scamstop-installer-VERSION-linux-x86_64.run --uninstall  remove (keeps settings and logs)
set -e
if [ "$(id -u)" -ne 0 ]; then echo "Run as root: sudo sh $0"; exit 1; fi
case "$(uname -m)" in x86_64|amd64) ;; *) echo "This installer is for 64-bit Intel/AMD Linux (x86_64)."; exit 1;; esac
TMP=$(mktemp -d /tmp/scamstop-install.XXXXXX)
trap 'rm -rf "$TMP"' EXIT INT TERM
echo "Unpacking ScamStop..."
LINE=$(awk '/^__SCAMSTOP_PAYLOAD__$/ { print NR + 1; exit }' "$0")
tail -n +"$LINE" "$0" | tar xzf - -C "$TMP"
bash "$TMP/install.sh" "$@"
exit $?
__SCAMSTOP_PAYLOAD__

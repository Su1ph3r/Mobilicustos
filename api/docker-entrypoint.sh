#!/bin/bash
set -e

# Configure libimobiledevice to talk to a usbmuxd. Two supported topologies:
#
#   Mac host:  mount the host's /var/run/usbmuxd socket into the container.
#              The host already runs usbmuxd, so we just use its socket.
#              Recommended docker-compose volume:
#                  - /var/run/usbmuxd:/var/run/usbmuxd
#
#   Windows host (usbipd-win + WSL2): pass /dev/bus/usb into the container
#              and run usbmuxd inside the container so it can claim the
#              USB interface directly. Requires privileged: true.
#                  - /dev/bus/usb:/dev/bus/usb
#
# If neither is present, iOS USB support is silently disabled.

if [ -S /var/run/usbmuxd ]; then
    echo "Using host usbmuxd socket at /var/run/usbmuxd"
elif [ -d /dev/bus/usb ] && command -v usbmuxd >/dev/null 2>&1; then
    usbmuxd -f -v >/var/log/usbmuxd.log 2>&1 &
    echo "Started in-container usbmuxd (pid $!) against /dev/bus/usb"
else
    echo "No iOS USB topology detected — idevice_* tools will report no devices"
fi

exec "$@"

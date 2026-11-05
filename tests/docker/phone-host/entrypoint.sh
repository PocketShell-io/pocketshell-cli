#!/bin/sh
set -eu
umask 077
pocketshell gateway endpoint init
printf '%s\n' 'Private phone-test endpoint initialized. Waiting for enrollment.'
while [ ! -f /home/orin/.config/pocketshell-link/config.json ]; do
    sleep 2 &
    wait "$!"
done
exec pocketshell gateway run

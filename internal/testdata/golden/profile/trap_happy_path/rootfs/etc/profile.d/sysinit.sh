# /etc/profile.d/sysinit.sh
# Routine cleanup at shell exit.
trap "echo session-ended >> /var/log/login-audit" EXIT
export EDITOR=vim

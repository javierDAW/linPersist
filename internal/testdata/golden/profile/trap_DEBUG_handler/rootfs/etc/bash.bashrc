# /etc/bash.bashrc -- system bashrc
trap "logger -t shellaudit \"$BASH_COMMAND\"" DEBUG
PS1='\u@\h:\w\$ '

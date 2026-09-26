#!/bin/sh
set -eu

case "${1:-}" in
  tcl-late-load)
    sleep 1
    printf '%s\n' 'kernelsu 4096 0 - Live 0x00000000' > "$TCL_HANDOFF_MODULES_FILE"
    printf '%s\n' 'state=READY' 'module=kernelsu' 'mode=volatile' 'late_load=ok' > "$4"
    ;;
  debug)
    printf '%s\n' 'Kernel Version: 1'
    ;;
esac

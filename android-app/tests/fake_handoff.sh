#!/bin/sh
set -eu

status=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --status)
      status=$2
      shift 2
      ;;
    --completion-fd|--preflight|--ksud|--module|--package-name)
      shift 2
      ;;
    --direct-child)
      shift
      ;;
    *)
      exit 2
      ;;
  esac
done

test -n "$status"
printf '%s\n' \
  'state=READY' \
  'module=kernelsu' \
  'mode=volatile' \
  'late_load=ok' > "$status"

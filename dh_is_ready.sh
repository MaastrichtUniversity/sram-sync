#!/bin/bash
#

set -euo pipefail

UPDATE_SYNCS_FILE_PATH="/var/run/sram-syncs"

# Will print given state and exit
# Args:
#   $1: status, one of {"READY", "NOT READY"}
#
return_status() {
    echo "$1"

    # return value (0 means success: it is ready)
    if [[ "$1" == "NOT READY" ]]; then
        exit 1
    else
        exit 0
    fi
}


if [[ ! -f "${UPDATE_SYNCS_FILE_PATH}" ]]; then
    return_status "NOT READY"
fi

# Just an attempt to make sure we are reading an integer
syncs_value=$(printf "%d" "$(< ${UPDATE_SYNCS_FILE_PATH})") || { return_status "NOT READY"; }

# lower than 1 would mean it hasn't run
if [[ "${syncs_value}" -lt 1 ]]; then
    return_status "NOT READY"
fi

# if we didn't return NOT READY by now.. I guess we're ready
return_status "READY"
